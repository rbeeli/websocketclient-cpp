#pragma once

#include <string>
#include <sstream>
#include <array>
#include <optional>
#include <cstddef>
#include <span>
#include <expected>
#include <variant>

#if WS_CLIENT_VALIDATE_UTF8 == 1
#include "ws_client/utils/utf8.hpp"
#endif

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/networking.hpp"
#include "ws_client/concepts.hpp"
#include "ws_client/URL.hpp"
#include "ws_client/MaskKey.hpp"
#include "ws_client/Frame.hpp"
#include "ws_client/Buffer.hpp"
#include "ws_client/Message.hpp"
#include "ws_client/Handshake.hpp"
#include "ws_client/BufferedSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"
#include "ws_client/HttpParser.hpp"

namespace ws_client
{
using std::array;
using std::string;
using std::variant;
using std::optional;
using std::byte;
using std::span;

/**
 * Web socket client class with blocking I/O operations and
 * customizable, templated socket and mask key generator types.
 * 
 * The `close()` method for closing the underlying socket connection
 * is not called automatically.It is the responsibility of the caller
 * to close the connection when it is no longer needed or in case of
 * errors. The caller MUST close the client upon receiving a close frame
 * or an error, read or write operations afterwards are undefined behaviour.
 * 
 * @tparam TLogger       Logger type for logging messages and errors.
 *
 * @tparam TSocket       Socket implementation type for transportation.
 *                       Must implement contract `HasSocketOperations`.
 * 
 *                       Blocking library implementations:
 *                          - `TcpSocket`, derives from `ISocket`
 *                          - `OpenSslSocket`, derives from `ISocket`
 * 
 *                       - For known protocol at compile time, either `ws://` or `wss://`, 
 *                         use concrete types like `TcpSocket` or `OpenSslSocket`.
 *                       - For unknown websocket protocol at compile time, use `ISocket`, 
 *                         the base class for `TcpSocket` and `OpenSslSocket`.
 *                       - Concrete types enable more efficient compilation by 
 *                         allowing inlining and avoiding virtual function calls.
 * 
 * @tparam TMaskKeyGen   Mask key generator type. Must implement contract `HasMaskKeyOperator`.
 * 
 *                       Library implementations:
 *                       - `ConstantMaskKeyGen`
 *                      -  `DefaultMaskKeyGen` (default), based on `xoshiro128p`
 */
template <typename TLogger, typename TSocket, typename TMaskKeyGen = DefaultMaskKeyGen>
    requires HasSocketOperations<TSocket> && HasMaskKeyOperator<TMaskKeyGen>
class WebSocketClient
{
private:
    bool closed = true;

    BufferedSocket<TSocket> socket;
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

    // maintain state for reading messages (might get interrupted with control frames, which require immediate handling)
    MessageReadState read_state;

    // permessage-deflate buffers
    Buffer decompress_buffer;
    Buffer compress_buffer;

public:
    explicit WebSocketClient(
        TLogger* logger, TSocket&& socket, TMaskKeyGen&& mask_key_generator
    ) noexcept
        : socket(BufferedSocket(std::move(socket))),
          logger(logger),
          mask_key_generator(mask_key_generator)
    {
    }

    explicit WebSocketClient(TLogger* logger, TSocket&& socket) noexcept
        : socket(BufferedSocket(std::move(socket))),
          logger(logger),
          mask_key_generator(DefaultMaskKeyGen())
    {
    }

    // disable copying
    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(WebSocketClient const&) = delete;

    // enable move
    WebSocketClient(WebSocketClient&& other) noexcept
        : closed(other.closed),
          socket(other.socket),
          logger(other.logger),
          mask_key_generator(std::move(other.mask_key_generator)),
          permessage_deflate_context(std::move(other.permessage_deflate_context)),
          read_state(other.read_state),
          decompress_buffer(std::move(other.decompress_buffer)),
          compress_buffer(std::move(other.compress_buffer))
    {
        this->write_buffer_storage = std::move(other.write_buffer_storage);
        this->write_buffer = span(this->write_buffer_storage);
        this->read_buffer_storage = std::move(other.read_buffer_storage);
        this->read_buffer = span(this->read_buffer_storage);
    }
    WebSocketClient& operator=(WebSocketClient&& other) noexcept
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
            this->read_state = other.read_state;
            this->decompress_buffer = std::move(other.decompress_buffer);
            this->compress_buffer = std::move(other.compress_buffer);
        }
        return *this;
    }

    [[nodiscard]] inline const URL& get_url() const noexcept
    {
        return this->url;
    }

    [[nodiscard]] inline BufferedSocket<TSocket>& underlying() noexcept
    {
        return this->socket;
    }

    /**
     * Returns `true` if the WebSocket connection has been established
     * and the handshake has been completed successfully.
     * 
     * Does not check whether connection is physically open and/or alive.
     * Reverts to `false` after `close()` has been called.
     */
    inline bool is_open() const noexcept
    {
        return !this->closed;
    }

    /**
     * Returns `true` if the WebSocket connection has been closed,
     * or if the connection has not been established yet.
     * 
     * Does not check whether connection is physically open and/or alive.
     * Value is set to `true` during `close()` call.
     */
    inline bool is_closed() const noexcept
    {
        return this->closed;
    }

    /**
     * Performs the WebSocket handshake using a HTTP request, which
     * should result in a connection upgrade to a WebSocket connection.
     * Compression parameters are negotiated during the handshake (permessage-deflate extension).
     * Messages can be sent and received after this method returns successfully.
     * User needs to ensure this method is called only once.
     */
    [[nodiscard]] expected<void, WSError> init(Handshake<TLogger>& handshake)
    {
        if (!this->closed)
            return WS_ERROR(LOGIC_ERROR, "Connection already open.", NOT_SET);
        
        // send HTTP request for websocket upgrade
        auto req_str = handshake.get_request_message();
        span<byte> req_data = span(reinterpret_cast<byte*>(req_str.data()), req_str.size());
        WS_TRYV(socket.write(req_data, handshake.get_timeout()));

        // read HTTP response
        Buffer headers_buffer;
        byte delim[4] = {byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
        span<byte> delim_span = span(delim);
        WS_TRYV(socket.read_until(headers_buffer, delim_span, handshake.get_timeout()));

        // read and discard header terminator bytes \r\n\r\n
        WS_TRYV(socket.read_exact(delim_span));

        // process HTTP response
        WS_TRYV(handshake.process_response(string_from_bytes(headers_buffer.data())));

        // initialize permessage-deflate compression if negotiated
        if (handshake.is_compression_negotiated())
        {
            auto& permessage_deflate = handshake.get_permessage_deflate();
            this->permessage_deflate_context.emplace(logger, permessage_deflate);
            WS_TRYV(this->permessage_deflate_context->init());

            // allocate buffers
            this->decompress_buffer.set_max_size(permessage_deflate.decompress_buffer_size);
            this->compress_buffer.set_max_size(permessage_deflate.compress_buffer_size);
            WS_TRYV(this->decompress_buffer.reserve(1024)); // reserve 1 KB initial size
            WS_TRYV(this->compress_buffer.reserve(1024));   // reserve 1 KB initial size
        }

        this->closed = false;

        return expected<void, WSError>{};
    }

    template <HasBufferOperations TBuffer>
    [[nodiscard]] variant<Message, PingFrame, PongFrame, CloseFrame, WSError> read_message(
        TBuffer& buffer
    ) noexcept
    {
        if (this->closed)
            return WS_ERROR_RAW(CONNECTION_CLOSED, "Connection in closed state.", NOT_SET);

        while (true)
        {
            while (true)
            {
                // read next frame w/o payload
                WS_TRY_RAW(frame_res, this->read_frame());
                Frame& frame = *frame_res;

                // check reserved opcodes
                if (is_reserved(frame.header.op_code()))
                {
                    return WS_ERROR_RAW(
                        PROTOCOL_ERROR,
                        "Reserved opcode received: " + to_string(frame.header.op_code()),
                        PROTOCOL_ERROR
                    );
                }

                // handle control frames
                if (frame.header.is_control())
                {
                    auto res = this->handle_control_frame(frame);

                    // convert to outer variant
                    return std::visit(
                        [](auto&& arg) //
                        -> variant<Message, PingFrame, PongFrame, CloseFrame, WSError>
                        { return arg; },
                        res
                    );
                }

                if (read_state.is_first)
                {
                    // clear buffer if this is the first frame
                    buffer.clear();
                }

                // check if payload fits into buffer
                if (buffer.max_size() - buffer.size() < frame.payload_size)
                {
                    string msg = "Received message payload of " +
                                 std::to_string(frame.payload_size) + " bytes is too large, only " +
                                 std::to_string(buffer.max_size() - buffer.size()) +
                                 " bytes available.";
                    return WS_ERROR_RAW(BUFFER_ERROR, msg, MESSAGE_TOO_BIG);
                }

                // check if this is the first frame
                if (read_state.is_first)
                {
                    read_state.is_first = false;
                    read_state.op_code = frame.header.op_code();

                    // RSV1 indicates DEFLATE compressed message, only if negotiated.
                    if (frame.header.rsv1_bit())
                    {
                        read_state.is_compressed = true;

                        if (this->permessage_deflate_context != std::nullopt)
                        {
                            this->decompress_buffer.clear();
                        }
                        else
                        {
                            return WS_ERROR_RAW(
                                PROTOCOL_ERROR,
                                "Received compressed frame, but compression not enabled.",
                                PROTOCOL_ERROR
                            );
                        }
                    }

                    if (frame.header.rsv2_bit() || frame.header.rsv3_bit())
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR,
                            "RSV2 or RSV3 bit set, but not supported.",
                            PROTOCOL_ERROR
                        );
                    }
                }
                else
                {
                    if (frame.header.op_code() != opcode::CONTINUATION)
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR,
                            "Expected continuation frame, but received " +
                                to_string(frame.header.op_code()),
                            PROTOCOL_ERROR
                        );
                    }

                    if (frame.header.has_rsv_bits())
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR,
                            "RSV bits must not be set on non-first frames.",
                            PROTOCOL_ERROR
                        );
                    }
                }

                // check opcode
                if (read_state.op_code != opcode::CONTINUATION &&
                    read_state.op_code != opcode::TEXT && read_state.op_code != opcode::BINARY)
                {
                    return WS_ERROR_RAW(
                        PROTOCOL_ERROR,
                        "Unexpected opcode in websocket frame received: " +
                            to_string(read_state.op_code),
                        PROTOCOL_ERROR
                    );
                }

                // read payload
                if (frame.payload_size > 0) [[likely]]
                {
                    if (read_state.is_compressed)
                    {
                        // read payload into decompression buffer
                        WS_TRY_RAW(
                            frame_data_compressed_res,
                            this->decompress_buffer.append(frame.payload_size)
                        );
                        WS_TRYV_RAW(this->socket.read_exact(*frame_data_compressed_res));
                    }
                    else
                    {
                        // read payload into message buffer
                        WS_TRY_RAW(frame_data_res, buffer.append(frame.payload_size));
                        WS_TRYV_RAW(this->socket.read_exact(*frame_data_res));
                    }
                }

                if (frame.header.is_final())
                    break;
            }

            span<byte> payload_buffer;

            // handle permessage-deflate compression
            if (read_state.is_compressed)
            {
                span<byte> input = this->decompress_buffer.data();
                WS_TRYV_RAW(this->permessage_deflate_context.value().decompress(input, buffer));
                payload_buffer = buffer.data();
            }
            else
            {
                payload_buffer = buffer.data();
            }

            switch (read_state.op_code)
            {
                case opcode::TEXT:
                {
#if WS_CLIENT_VALIDATE_UTF8
                    if (!is_valid_utf8(
                            const_cast<char*>((char*)payload_buffer.data()), payload_buffer.size()
                        ))
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR,
                            "Invalid UTF-8 in websocket TEXT message.",
                            INVALID_FRAME_PAYLOAD_DATA
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

                    auto msg = Message(
                        static_cast<MessageType>(read_state.op_code), payload_buffer
                    );

                    // reset reading state - message complete
                    read_state.reset();

                    return msg;
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

                    auto msg = Message(
                        static_cast<MessageType>(read_state.op_code), payload_buffer
                    );

                    // reset reading state - message complete
                    read_state.reset();

                    return msg;
                }

                default:
                {
                    return WS_ERROR_RAW(
                        PROTOCOL_ERROR,
                        "Unexpected opcode frame received: " + to_string(read_state.op_code),
                        PROTOCOL_ERROR
                    );
                }
            }
        }
    }

    [[nodiscard]] expected<void, WSError> send_message(
        const Message& msg, SendOptions options = {}
    ) noexcept
    {
        if (this->closed)
            return WS_ERROR(CONNECTION_CLOSED, "Connection in closed state.", NOT_SET);

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
        frame.set_is_final(true); // TODO: support fragmented messages
        frame.set_is_masked(true);
        frame.mask_key = this->mask_key_generator();

        span<byte> payload;
        if (this->permessage_deflate_context != std::nullopt && options.compress)
        {
            frame.set_is_compressed(true);

            // perform deflate compression using zlib
            Buffer& output = this->compress_buffer;
            output.clear();
            WS_TRY(res, this->permessage_deflate_context.value().compress(msg.data, output));
            payload = *res;
        }
        else
            payload = msg.data;

        frame.set_payload_size(payload.size());

        WS_TRYV(this->write_frame(frame, payload, options.timeout));

        return expected<void, WSError>{};
    }


    [[nodiscard]] expected<void, WSError> send_pong_frame(
        span<byte> payload, std::chrono::milliseconds timeout = std::chrono::seconds{10}
    ) noexcept
    {
        if (this->closed)
            return WS_ERROR(CONNECTION_CLOSED, "Connection in closed state.", NOT_SET);
        
        Frame frame;
        frame.set_opcode(opcode::PONG);
        frame.set_is_final(true);
        frame.set_is_masked(true); // write_frame does the actual masking
        frame.set_payload_size(payload.size());
        frame.mask_key = this->mask_key_generator();

        WS_TRYV(this->write_frame(frame, payload, timeout));

        return expected<void, WSError>{};
    }

    /**
     * Closes the WebSocket connection.
     * 
     * This method sends a close frame to the server and waits for the server,
     * shuts down the socket communication and closes the underlying socket connection.
     * 
     * This method is thread-safe and can be called multiple times.
     */
    [[nodiscard]] inline expected<void, WSError> close(
        const close_code code, std::chrono::milliseconds timeout = std::chrono::seconds(10)
    )
    {
        if (this->closed)
            return expected<void, WSError>{};

        // send close frame
        {
            auto res = this->send_close_frame(code, timeout);
            if (!res.has_value())
            {
                logger->template log<LogLevel::W>(
                    "Failed to send close frame: " + res.error().message
                );
            }
        }

        // mark as closed
        this->closed = true;

        // shutdown socket communication (ignore errors, close socket anyway).
        // often times, the server will close the connection after receiving the close frame,
        // which will result in an error when trying to shutdown the socket.
        this->socket.underlying().shutdown(timeout);

        // close underlying socket connection
        {
            auto res = this->socket.underlying().close();
            if (!res.has_value())
            {
                logger->template log<LogLevel::W>("Socket close failed: " + res.error().message);
                return WS_UNEXPECTED(res.error());
            }
        }

        return expected<void, WSError>{};
    }

private:
    [[nodiscard]] expected<Frame, WSError> read_frame()
    {
        Frame frame;

        // read frame header (2 bytes)
        byte tmp1[2];
        WS_TRYV(this->socket.read_exact(span<byte>(tmp1, 2)));

        frame.header.b0 = tmp1[0];
        frame.header.b1 = tmp1[1];

        if (!frame.header.is_final() && frame.header.op_code() == opcode::CLOSE) [[unlikely]]
            return WS_ERROR(PROTOCOL_ERROR, "Received fragmented close frame.", PROTOCOL_ERROR);

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
            WS_TRYV(this->socket.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp2), sizeof(uint16_t))
            ));
            payload_size = network_to_host(tmp2);
        }
        else
        {
            // 64 bit payload size
            uint64_t tmp3;
            WS_TRYV(this->socket.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp3), sizeof(uint64_t))
            ));
            payload_size = network_to_host(tmp3);
        }

        frame.payload_size = payload_size;

        // verify not masked
        if (frame.header.is_masked()) [[unlikely]]
            return WS_ERROR(PROTOCOL_ERROR, "Received masked frame from server.", PROTOCOL_ERROR);

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

        return frame;
    }

    [[nodiscard]] expected<void, WSError> write_frame(
        Frame& frame, span<byte> payload, std::chrono::milliseconds timeout
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

        if (!frame.header.is_masked())
            return WS_ERROR(PROTOCOL_ERROR, "Frame sent by client MUST be masked.", PROTOCOL_ERROR);

        // write 4 byte masking key
        std::memcpy(&write_buffer[offset], &frame.mask_key.key, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // mask payload in-place
        frame.mask_key.mask(payload);

        // write frame header
        logger->template log<LogLevel::D>("Writing frame header");
        WS_TRYV(this->socket.write(write_buffer.subspan(0, offset), timeout));

        // write frame payload
        if (frame.payload_size > 0)
        {
            logger->template log<LogLevel::D>("Writing frame payload");
            WS_TRYV(this->socket.write(payload, timeout));
            offset += frame.payload_size;
        }

        return expected<void, WSError>{};
    }

    [[nodiscard]] expected<void, WSError> send_close_frame(
        close_code code, std::chrono::milliseconds timeout
    ) noexcept
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

        WS_TRY(ret, this->write_frame(frame, payload, timeout));

        logger->template log<LogLevel::D>("Close frame sent");

        return expected<void, WSError>{};
    }

    [[nodiscard]] variant<PingFrame, PongFrame, CloseFrame, WSError> handle_control_frame(
        Frame& frame
    ) noexcept
    {
        if (!frame.header.is_final())
        {
            return WS_ERROR_RAW(
                PROTOCOL_ERROR, "Received fragmented control frame.", PROTOCOL_ERROR
            );
        }

        if (frame.header.has_rsv_bits())
        {
            return WS_ERROR_RAW(
                PROTOCOL_ERROR, "Invalid RSV bits found in control frame.", PROTOCOL_ERROR
            );
        }

        if (frame.payload_size > 125)
        {
            return WS_ERROR_RAW(
                PROTOCOL_ERROR,
                "Control frame payload size larger than 125 bytes, got " +
                    std::to_string(frame.payload_size),
                PROTOCOL_ERROR
            );
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

                CloseFrame close_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    if (frame.payload_size == 1)
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR, "Invalid close frame payload size of 1.", PROTOCOL_ERROR
                        );
                    }

                    WS_TRYV_RAW(this->socket.read_exact(close_frame.payload_bytes()));

                    // check close code if provided
                    if (close_frame.has_close_code())
                    {
                        auto code = close_frame.get_close_code();
                        if (!is_valid_close_code(code))
                        {
                            return WS_ERROR_RAW(
                                PROTOCOL_ERROR,
                                "Invalid close code " + std::to_string(static_cast<uint16_t>(code)),
                                PROTOCOL_ERROR
                            );
                        }
                    }

#if WS_CLIENT_VALIDATE_UTF8
                    // check close reason string is valid UTF-8 string
                    if (!close_frame.is_reason_valid_utf8())
                    {
                        return WS_ERROR_RAW(
                            PROTOCOL_ERROR,
                            "Invalid UTF-8 in websocket close reason string.",
                            INVALID_FRAME_PAYLOAD_DATA
                        );
                    }
#endif
                }

                return close_frame;
            }

            case opcode::PING:
            {
                PingFrame ping_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_TRYV_RAW(this->socket.read_exact(ping_frame.payload_bytes()));
                }

                return ping_frame;
            }

            case opcode::PONG:
            {
                PongFrame pong_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_TRYV_RAW(this->socket.read_exact(pong_frame.payload_bytes()));
                }

                return pong_frame;
            }

            default:
            {
                return WS_ERROR_RAW(
                    PROTOCOL_ERROR,
                    "Unexpected opcode for websocket control frame received: " +
                        to_string(frame.header.op_code()),
                    PROTOCOL_ERROR
                );
            }
        }
    }
};
} // namespace ws_client