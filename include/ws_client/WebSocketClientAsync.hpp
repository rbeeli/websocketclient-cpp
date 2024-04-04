#pragma once

#include <string>
#include <sstream>
#include <array>
#include <optional>
#include <cstddef>
#include <span>
#include <expected>

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/networking.hpp"
#include "ws_client/concepts_async.hpp"
#include "ws_client/URL.hpp"
#include "ws_client/MaskKey.hpp"
#include "ws_client/Frame.hpp"
#include "ws_client/Buffer.hpp"
#include "ws_client/Message.hpp"
#include "ws_client/Handshake.hpp"
#include "ws_client/BufferedSocketAsync.hpp"
#include "ws_client/PermessageDeflate.hpp"
#include "ws_client/HttpParser.hpp"

#if WS_CLIENT_VALIDATE_UTF8 == 1
#include "ws_client/utils/utf8.hpp"
#endif

namespace ws_client
{
using std::array;
using std::string;
using std::optional;
using std::byte;
using std::span;

/**
 * Web socket client class with non-blocking I/O operations based
 * on coroutines. Customizable templated socket, mask key generator types
 * and coroutine task type.
 * 
 * The `close()` method for closing the underlying socket connection
 * is not called automatically. It is the responsibility of the caller
 * to close the connection when it is no longer needed, also in case of
 * errors.
 * 
 * @tparam TLogger       Logger type for logging messages and errors.
 *
 * @tparam TSocket       Socket implementation type for transportation.
 *                       Must implement contract `HasAsyncSocketOperations`.
 * 
 *                       Available third party transport bindings:
 *                       - `CoroioSocket`, for non-blocking I/O based on `coroio`
 *                       - `AsioSocket`, for non-blocking I/O based on standalone `asio`
 * 
 * @tparam TTask         Task type for coroutine-based asynchronous operations,
 *                       e.g. `TValueTask` for `coroio`, or `asio::awaitable` for `asio`.
 * 
 * @tparam TMaskKeyGen   Mask key generator type. Must implement contract `HasMaskKeyOperator`.
 * 
 *                       Library implementations:
 *                       - `ConstantMaskKeyGen`
 *                      -  `DefaultMaskKeyGen` (default), based on `xoshiro128p`
 */
template <
    template <typename>
    typename TTask,
    typename TLogger,
    typename TSocket,
    typename TMaskKeyGen = DefaultMaskKeyGen>
    requires HasAsyncSocketOperations<TSocket, TTask> && HasMaskKeyOperator<TMaskKeyGen>
class WebSocketClientAsync
{
private:
    bool closed = true;

    BufferedSocketAsync<TSocket, TTask> socket;
    TLogger* logger;

    // mask key generator
    TMaskKeyGen mask_key_generator;

    // negotiation handshake
    optional<PermessageDeflateContext<TLogger>> permessage_deflate_context = std::nullopt;

    // buffers for header data and control frame payloads
    alignas(64) array<byte, 128> write_buffer_storage;
    span<byte> write_buffer = span(write_buffer_storage);

    alignas(64) array<byte, 128> read_buffer_storage;
    span<byte> read_buffer = span(read_buffer_storage);

    // permessage-deflate buffers
    Buffer decompress_buffer;
    Buffer compress_buffer;

public:
    explicit WebSocketClientAsync(
        TLogger* logger, TSocket&& socket, TMaskKeyGen&& mask_key_generator
    ) noexcept
        : socket(BufferedSocketAsync<TSocket, TTask>(std::move(socket))),
          logger(logger),
          mask_key_generator(mask_key_generator)
    {
    }

    explicit WebSocketClientAsync(TLogger* logger, TSocket&& socket) noexcept
        : socket(BufferedSocketAsync<TSocket, TTask>(std::move(socket))),
          logger(logger),
          mask_key_generator(DefaultMaskKeyGen())
    {
    }

    // disable copy
    WebSocketClientAsync(const WebSocketClientAsync&) = delete;
    WebSocketClientAsync& operator=(WebSocketClientAsync const&) = delete;

    // enable move
    WebSocketClientAsync(WebSocketClientAsync&& other) noexcept
        : closed(other.closed),
          socket(other.socket),
          logger(other.logger),
          mask_key_generator(std::move(other.mask_key_generator)),
          permessage_deflate_context(std::move(other.permessage_deflate_context))
    {
        this->write_buffer_storage = std::move(other.write_buffer_storage);
        this->write_buffer = span(this->write_buffer_storage);
        this->read_buffer_storage = std::move(other.read_buffer_storage);
        this->read_buffer = span(this->read_buffer_storage);
    }
    WebSocketClientAsync& operator=(WebSocketClientAsync&& other) noexcept
    {
        if (this != &other)
        {
            this->closed = other.closed;
            this->socket = other.socket;
            this->logger = other.logger;
            this->mask_key_generator = std::move(other.mask_key_generator);
            this->permessage_deflate_context = std::move(other.permessage_deflate_context);
            this->write_buffer_storage = std::move(other.write_buffer_storage);
            this->write_buffer = span(this->write_buffer_storage);
            this->read_buffer_storage = std::move(other.read_buffer_storage);
            this->read_buffer = span(this->read_buffer_storage);
        }
        return *this;
    }

    [[nodiscard]] inline const URL& get_url() const noexcept
    {
        return this->url;
    }

    [[nodiscard]] inline BufferedSocketAsync<TSocket, TTask>& underlying() noexcept
    {
        return this->socket;
    }

    /**
     * Returns `true` if the WebSocket connection has been established
     * and the handshake has been completed successfully.
     * 
     * Does not check whether connection is physically open and alive.
     * Reverts to `false` after `close()` has been called.
    */
    inline bool is_open() const noexcept
    {
        return !this->closed;
    }

    /**
     * Performs the WebSocket handshake using a HTTP request, which
     * should result in a connection upgrade to a WebSocket connection.
     * Compression parameters are negotiated during the handshake (permessage-deflate extension).
     * Messages can be sent and received after this method returns successfully.
     */
    [[nodiscard]] TTask<expected<void, WSError>> init(Handshake<TLogger>& handshake)
    {
        // send HTTP request for websocket upgrade
        auto req_str = handshake.get_request_message();
        span<byte> req_data = span(reinterpret_cast<byte*>(req_str.data()), req_str.size());
        WS_CO_TRYV(co_await this->socket.write(req_data));

        // read HTTP response
        Buffer headers_buffer;
        byte delim[4] = {byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
        span<byte> delim_span = span(delim);
        WS_CO_TRYV(
            co_await this->socket.read_until(headers_buffer, delim_span, handshake.get_timeout())
        );

        // read and discard header terminator bytes \r\n\r\n
        WS_CO_TRYV(co_await this->socket.read_exact(delim_span));

        // process HTTP response
        WS_CO_TRYV(handshake.process_response(string_from_bytes(headers_buffer.data())));

        // initialize permessage-deflate compression if negotiated
        if (handshake.is_compression_negotiated())
        {
            auto& permessage_deflate = handshake.get_permessage_deflate();
            this->permessage_deflate_context.emplace(logger, permessage_deflate);
            WS_CO_TRYV(this->permessage_deflate_context->init());

            // allocate buffers
            this->decompress_buffer.set_max_size(permessage_deflate.decompress_buffer_size);
            this->compress_buffer.set_max_size(permessage_deflate.compress_buffer_size);
            WS_CO_TRYV(this->decompress_buffer.reserve(1024)); // reserve 1 KB initial size
            WS_CO_TRYV(this->compress_buffer.reserve(1024));   // reserve 1 KB initial size
        }

        this->closed = false;

        co_return expected<void, WSError>{};
    }


    /**
     * Closes the WebSocket connection.
     * This method sends a close frame to the server and waits for the server,
     * shuts down the socket communication and closes the underlying socket connection.
     */
    [[nodiscard]] inline TTask<expected<void, WSError>> close()
    {
        if (this->closed)
            co_return expected<void, WSError>{};

        // send close frame
        auto res = co_await this->send_close_frame(close_code::NORMAL_CLOSURE);

        // only log warning if sending close frame failed
        if (!res.has_value())
        {
            logger->template log<LogLevel::W>("Failed to send close frame: " + res.error().message);
        }

        // mark as closed, prevents further reading/writing
        this->closed = true;

        // shutdown socket communication (ignore errors)
        co_await this->socket.underlying().shutdown();

        // close underlying socket connection
        WS_CO_TRYV(co_await this->socket.underlying().close());

        co_return expected<void, WSError>{};
    }

    template <HasBufferOperations TBuffer>
    [[nodiscard]] TTask<expected<Message, WSError>> read_message(TBuffer& buffer) noexcept
    {
        if (this->closed)
            co_return WS_ERROR(CONNECTION_CLOSED, "Connection in closed state.");

        // remember the current location of the buffer,
        // might not be empty, we just append to it
        size_t buffer_pos = buffer.size();

        while (true)
        {
            bool is_compressed = false;
            bool is_first = true;
            opcode opcode_ = opcode::NOT_SET;
            while (true)
            {
                // read next frame
                WS_CO_TRY(frame_res, co_await this->read_frame());
                Frame& frame = *frame_res;

                // check reserved opcodes
                if (is_reserved(frame.header.op_code()))
                {
                    WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                    co_return WS_ERROR(
                        PROTOCOL_ERROR,
                        "Reserved opcode received: " + to_string(frame.header.op_code())
                    );
                }

                // handle control frames
                if (frame.header.is_control())
                {
                    WS_CO_TRYV(co_await this->handle_control_frame(frame));
                    continue;
                }

                // check if payload fits into buffer
                if (buffer.max_size() - buffer.size() < frame.payload_size)
                {
                    WS_CO_TRYV(co_await this->send_close_frame(close_code::MESSAGE_TOO_BIG));
                    string msg = "Received message payload of " +
                                 std::to_string(frame.payload_size) + " bytes is too large, only " +
                                 std::to_string(buffer.max_size() - buffer.size()) +
                                 " bytes available.";
                    co_return WS_ERROR(BUFFER_ERROR, msg);
                }

                // check if this is the first frame
                if (is_first)
                {
                    is_first = false;
                    opcode_ = frame.header.op_code();

                    // RSV1 indicates DEFLATE compressed message, only if negotiated.
                    if (frame.header.rsv1_bit())
                    {
                        if (this->permessage_deflate_context != std::nullopt)
                        {
                            is_compressed = true;
                            this->decompress_buffer.clear();
                        }
                        else
                        {
                            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                            co_return WS_ERROR(
                                PROTOCOL_ERROR,
                                "Received compressed frame, but compression not enabled."
                            );
                        }
                    }

                    if (frame.header.rsv2_bit() || frame.header.rsv3_bit())
                    {
                        WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                        co_return WS_ERROR(
                            PROTOCOL_ERROR, "RSV2 or RSV3 bit set, but not supported."
                        );
                    }
                }
                else
                {
                    if (frame.header.op_code() != opcode::CONTINUATION)
                    {
                        WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                        co_return WS_ERROR(
                            PROTOCOL_ERROR,
                            "Expected continuation frame, but received " +
                                to_string(frame.header.op_code())
                        );
                    }

                    if (frame.header.has_rsv_bits())
                    {
                        WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                        co_return WS_ERROR(
                            PROTOCOL_ERROR, "RSV bits must not be set on non-first frames."
                        );
                    }
                }

                // check opcode
                if (opcode_ != opcode::CONTINUATION && opcode_ != opcode::TEXT &&
                    opcode_ != opcode::BINARY)
                {
                    WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                    co_return WS_ERROR(
                        PROTOCOL_ERROR,
                        "Unexpected opcode in websocket frame received: " + to_string(opcode_)
                    );
                }

                // read payload
                if (frame.payload_size > 0) [[likely]]
                {
                    if (is_compressed)
                    {
                        // read payload into decompression buffer
                        WS_CO_TRY(
                            frame_data_compressed_res,
                            this->decompress_buffer.append(frame.payload_size)
                        );
                        WS_CO_TRYV(co_await this->socket.read_exact(*frame_data_compressed_res));
                    }
                    else
                    {
                        // read payload into message buffer
                        WS_CO_TRY(frame_data_res, buffer.append(frame.payload_size));
                        WS_CO_TRYV(co_await this->socket.read_exact(*frame_data_res));
                    }
                }

                if (frame.header.is_final())
                    break;
            }

            span<byte> payload_buffer;

            // handle permessage-deflate compression
            if (is_compressed)
            {
                span<byte> input = this->decompress_buffer.data();
                WS_CO_TRYV(this->permessage_deflate_context.value().decompress(input, buffer));
                payload_buffer = buffer.data().subspan(buffer_pos, buffer.size() - buffer_pos);
            }
            else
            {
                payload_buffer = buffer.data().subspan(buffer_pos, buffer.size() - buffer_pos);
            }

            switch (opcode_)
            {
                case opcode::TEXT:
                {
#if WS_CLIENT_VALIDATE_UTF8
                    if (!is_valid_utf8(
                            const_cast<char*>((char*)payload_buffer.data()), payload_buffer.size()
                        ))
                    {
                        WS_CO_TRYV(
                            co_await this->send_close_frame(close_code::INVALID_FRAME_PAYLOAD_DATA)
                        );
                        co_return WS_ERROR(
                            PROTOCOL_ERROR, "Invalid UTF-8 in websocket text message."
                        );
                    }
#endif

                    if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
                    {
#if WS_CLIENT_LOG_MSG_PAYLOADS
                        std::stringstream ss;
                        ss << "Received TEXT message (";
                        ss << payload_buffer.size();
                        ss << " bytes):\033[1;35m\n";
                        ss << string(
                            reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                        );
                        ss << "\033[0m";
                        logger->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES
                        logger->template log(
                            LogLevel::I, "Received TEXT message (", payload_buffer.size(), " bytes)"
                        );
#endif
                    }

                    co_return Message(static_cast<MessageType>(opcode_), payload_buffer);
                }

                case opcode::BINARY:
                {

                    if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
                    {
#if WS_CLIENT_LOG_MSG_PAYLOADS
                        std::stringstream ss;
                        ss << "Received BINARY message (";
                        ss << payload_buffer.size();
                        ss << " bytes):\033[1;35m\n";
                        ss << string(
                            reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                        );
                        ss << "\033[0m";
                        logger->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES
                        logger->template log(
                            LogLevel::I,
                            "Received BINARY message (" + std::to_string(payload_buffer.size()) +
                                " bytes)"
                        );
#endif
                    }
                    co_return Message(static_cast<MessageType>(opcode_), payload_buffer);
                }

                default:
                {
                    WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                    co_return WS_ERROR(
                        PROTOCOL_ERROR,
                        "Unexpected opcode in websocket message received: " + to_string(opcode_)
                    );
                }
            }
        }
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_message(
        const Message& msg, SendOptions options = {}
    ) noexcept
    {
        if (this->closed)
            co_return WS_ERROR(CONNECTION_CLOSED, "Connection in closed state.");

        if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
        {
#if WS_CLIENT_LOG_MSG_PAYLOADS
            std::stringstream ss;
            ss << "Writing ";
            ss << to_string(msg.type);
            ss << " message (";
            ss << msg.data.size();
            ss << " bytes):\033[1;34m\n";
            ss << msg.to_string_view();
            ss << "\033[0m";
            logger->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES
            logger->template log<LogLevel::I>(
                "Writing " + to_string(msg.type) + " message (" + std::to_string(msg.data.size()) +
                " bytes)"
            );
#endif
        }

        Frame frame;
        frame.set_opcode(static_cast<opcode>(msg.type));
        frame.set_is_final(true);
        frame.set_is_masked(true);
        frame.mask_key = this->mask_key_generator();

        span<byte> payload;
        if (this->permessage_deflate_context != std::nullopt && options.compress)
        {
            frame.set_is_compressed(true);

            // perform deflate compression using zlib
            Buffer& output = this->compress_buffer;
            output.clear();
            WS_CO_TRY(res, this->permessage_deflate_context.value().compress(msg.data, output));
            payload = *res;
        }
        else
        {
            payload = msg.data;
        }

        frame.set_payload_size(payload.size());

        WS_CO_TRYV(co_await this->write_frame(frame, payload));

        co_return expected<void, WSError>{};
    }


private:
    [[nodiscard]] TTask<expected<Frame, WSError>> read_frame()
    {
        Frame frame;

        // read frame header (2 bytes)
        byte tmp1[2];
        WS_CO_TRYV(co_await this->socket.read_exact(span<byte>(tmp1, 2)));

        frame.header.b0 = tmp1[0];
        frame.header.b1 = tmp1[1];

        if (!frame.header.is_final() && frame.header.op_code() == opcode::CLOSE) [[unlikely]]
        {
            // close frame cannot be fragmented
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(PROTOCOL_ERROR, "Received fragmented close frame.");
        }

        // read payload size (1 byte, 2 bytes, or 8 bytes)
        auto payload_size = frame.header.get_basic_size();
        if (payload_size <= 125)
        {
            // 7 bit payload size
        }
        else if (payload_size == 126)
        {
            // 16 bit payload size
            uint16_t tmp2;
            WS_CO_TRYV(co_await this->socket.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp2), sizeof(uint16_t))
            ));
            payload_size = network_to_host(tmp2);
        }
        else
        {
            // 64 bit payload size
            uint64_t tmp3;
            WS_CO_TRYV(co_await this->socket.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp3), sizeof(uint64_t))
            ));
            payload_size = network_to_host(tmp3);
        }

        frame.payload_size = payload_size;

        // verify not masked
        if (frame.header.is_masked()) [[unlikely]]
        {
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(PROTOCOL_ERROR, "Received masked frame from server.");
        }

        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
#if WS_CLIENT_LOG_FRAMES
            std::stringstream msg;
            msg << "Received ";
            msg << to_string(frame.header.op_code());
            msg << " frame rsv=";
            msg << frame.header.rsv1_bit();
            msg << " ";
            msg << frame.header.rsv2_bit();
            msg << " ";
            msg << frame.header.rsv3_bit();
            msg << " control=";
            msg << frame.header.is_control();
            msg << " final=";
            msg << frame.header.is_final();
            msg << " masked=";
            msg << frame.header.is_masked();
            msg << " payload_size=";
            msg << frame.payload_size;
            logger->template log<LogLevel::D>(msg.str());
#endif
        }

        co_return frame;
    }

    [[nodiscard]] TTask<expected<void, WSError>> write_frame(
        Frame& frame, span<byte> payload
    ) noexcept
    {
        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
#if WS_CLIENT_LOG_FRAMES
            std::stringstream msg;
            msg << "Writing ";
            msg << to_string(frame.header.op_code());
            msg << " frame rsv=";
            msg << frame.header.rsv1_bit();
            msg << " ";
            msg << frame.header.rsv2_bit();
            msg << " ";
            msg << frame.header.rsv3_bit();
            msg << " control=";
            msg << frame.header.is_control();
            msg << " final=";
            msg << frame.header.is_final();
            msg << " masked=";
            msg << frame.header.is_masked();
            msg << " payload_size=";
            msg << frame.payload_size;
            logger->template log<LogLevel::D>(msg.str());
#endif
        }

        size_t offset = 0;
        write_buffer[0] = frame.header.b0;
        write_buffer[1] = frame.header.b1;
        offset += 2;

        if (frame.payload_size > 125 && frame.payload_size <= UINT16_MAX) [[likely]]
        {
            // 16 bit payload length
            uint16_t nlen = host_to_network(static_cast<uint16_t>(frame.payload_size));
            std::memcpy(&write_buffer[offset], &nlen, sizeof(uint16_t));
            offset += sizeof(uint16_t);
        }
        else if (frame.payload_size > UINT16_MAX) [[unlikely]]
        {
            // full 64 bit payload length
            uint64_t nlen = host_to_network(static_cast<uint64_t>(frame.payload_size));
            std::memcpy(&write_buffer[offset], &nlen, sizeof(uint64_t));
            offset += sizeof(uint64_t);
        }

#ifndef NDEBUG
        if (!frame.header.is_masked())
            co_return WS_ERROR(PROTOCOL_ERROR, "Frame sent by client MUST be masked.");
#endif

        // write 4 byte masking key
        std::memcpy(&write_buffer[offset], &frame.mask_key.key, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // mask payload in-place
        frame.mask_key.mask(payload);

        // write frame header
        WS_CO_TRYV(co_await this->socket.write(write_buffer.subspan(0, offset)));

        // write frame payload
        if (frame.payload_size > 0)
        {
            WS_CO_TRYV(co_await this->socket.write(payload));
            offset += frame.payload_size;
        }

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_pong_frame(span<byte> payload) noexcept
    {
        Frame frame;
        frame.set_opcode(opcode::PONG);
        frame.set_is_final(true);
        frame.set_is_masked(true);
        frame.set_payload_size(payload.size());
        frame.mask_key = this->mask_key_generator();

#if WS_CLIENT_LOG_PING_PONG
        logger->template log<LogLevel::I>("Writing pong frame");
#endif

        WS_CO_TRYV(co_await this->write_frame(frame, payload));

#if WS_CLIENT_LOG_PING_PONG
        logger->template log<LogLevel::D>("Pong frame sent");
#endif

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_close_frame(close_code code) noexcept
    {
        Frame frame;
        frame.set_opcode(opcode::CLOSE);
        frame.set_is_final(true);
        frame.set_is_masked(true);
        frame.mask_key = this->mask_key_generator();

        span<byte> payload;

        if (code != close_code::NOT_SET)
        {
            // close frame with status code
            uint16_t status_code_n = host_to_network(static_cast<uint16_t>(code));

            // use last two bytes of write buffer for status code
            std::memcpy(this->write_buffer.data() + 125, &status_code_n, sizeof(uint16_t));
            payload = this->write_buffer.subspan(125, sizeof(uint16_t));

            std::stringstream msg;
            msg << "Writing close frame with status ";
            msg << static_cast<int>(code);
            msg << " ";
            msg << to_string(code);
            logger->template log<LogLevel::I>(msg.str());
        }
        else
        {
            // close frame without status code
            logger->template log<LogLevel::I>("Writing close frame");
        }

        frame.set_payload_size(payload.size());

        WS_CO_TRY(ret, co_await this->write_frame(frame, payload));

        logger->template log<LogLevel::D>("Close frame sent");

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<void, WSError>> handle_control_frame(Frame& frame) noexcept
    {
        if (!frame.header.is_final())
        {
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(PROTOCOL_ERROR, "Received fragmented control frame.");
        }

        if (frame.header.has_rsv_bits())
        {
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(PROTOCOL_ERROR, "RSV bits must not be set for control frames.");
        }

        if (frame.payload_size > 125)
        {
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(
                PROTOCOL_ERROR,
                "Control frame payload size larger than 125 bytes, got " +
                    std::to_string(frame.payload_size)
            );
        }

        // read control frame payload (max. 125 bytes)
        span<byte> payload;
        if (frame.payload_size > 0)
        {
            WS_CO_TRYV(
                co_await this->socket.read_exact(this->read_buffer.subspan(0, frame.payload_size))
            );
            payload = this->read_buffer.subspan(0, frame.payload_size);
        }

        switch (frame.header.op_code())
        {
            case opcode::CLOSE:
            {
                if (!this->closed)
                {
                    // close frame sent by server
                    logger->template log<LogLevel::W>("Unsolicited close frame received");
                }
                WS_CO_TRY(res, co_await this->process_close_frame(frame, payload));
                string close_reason = *res;
                this->closed = true;
                co_return WS_ERROR(CONNECTION_CLOSED_BY_PEER, close_reason);
            }

            case opcode::PING:
            {
#if WS_CLIENT_LOG_PING_PONG
                logger->template log<LogLevel::D>("Ping frame received, sending pong");
#endif
                WS_CO_TRYV(co_await this->send_pong_frame(payload));
            }
            break;

            case opcode::PONG:
            {
                // pong frame received - nothing to do
#if WS_CLIENT_LOG_PING_PONG
                logger->template log<LogLevel::D>("Pong frame received");
#endif
            }
            break;

            default:
            {
                logger->template log<LogLevel::E>(
                    "Unexpected opcode for websocket control frame received: " +
                    to_string(frame.header.op_code())
                );

                WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));

                co_return WS_ERROR(
                    PROTOCOL_ERROR,
                    "Unexpected opcode for websocket control frame received: " +
                        to_string(frame.header.op_code())
                );
            }
        }

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<string, WSError>> process_close_frame(
        Frame& frame, span<byte> payload
    ) noexcept
    {
        logger->template log<LogLevel::D>("Close frame received, sending close response frame");

        if (frame.payload_size == 1)
        {
            logger->template log<LogLevel::D>("Invalid close frame payload size 1.");
            WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
            co_return WS_ERROR(PROTOCOL_ERROR, "Invalid close frame payload size 1.");
        }

        // extract close code and reason text (if provided)
        string reason = "";
        if (frame.payload_size >= 2)
        {
            // check close code
            uint16_t ncode;
            std::memcpy(&ncode, payload.data(), sizeof(uint16_t));
            uint16_t code = network_to_host(ncode);
            if (!is_valid_close_code((close_code)code))
            {
                logger->template log<LogLevel::D>("Invalid close code " + std::to_string(code));
                WS_CO_TRYV(co_await this->send_close_frame(close_code::PROTOCOL_ERROR));
                co_return WS_ERROR(PROTOCOL_ERROR, "Invalid close code " + std::to_string(code));
            }

            if (frame.payload_size > 2)
            {
                const char* reason_buffer = const_cast<char*>(
                    reinterpret_cast<char*>(payload.data() + 2)
                );
                size_t reason_size = payload.size() - 2;

#if WS_CLIENT_VALIDATE_UTF8
                // check close reason is valid UTF-8 string
                if (!is_valid_utf8(reason_buffer, reason_size))
                {
                    logger->template log<LogLevel::E>(
                        "Invalid UTF-8 in websocket close reason string."
                    );
                    WS_CO_TRYV(
                        co_await this->send_close_frame(close_code::INVALID_FRAME_PAYLOAD_DATA)
                    );
                    co_return WS_ERROR(
                        PROTOCOL_ERROR, "Invalid UTF-8 in websocket close reason string."
                    );
                }
#endif

                reason.append(" ");
                reason.append(string(reason_buffer, reason_size));
            }
        }

        WS_CO_TRYV(co_await this->send_close_frame(close_code::NORMAL_CLOSURE));

        // mark as closed, prevents further reading/writing
        this->closed = true;

        co_return "Closed by server." + reason;
    }
};
} // namespace ws_client