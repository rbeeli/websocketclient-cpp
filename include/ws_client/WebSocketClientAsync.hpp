#pragma once

#include <string>
#include <sstream>
#include <array>
#include <optional>
#include <cstddef>
#include <span>
#include <expected>
#include <variant>
#include <chrono>

#if WS_CLIENT_VALIDATE_UTF8 == 1
#include "ws_client/utils/utf8.hpp"
#endif

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/networking.hpp"
#include "ws_client/transport/HasSocketOperationsAsync.hpp"
#include "ws_client/URL.hpp"
#include "ws_client/MaskKey.hpp"
#include "ws_client/Frame.hpp"
#include "ws_client/Buffer.hpp"
#include "ws_client/Message.hpp"
#include "ws_client/Handshake.hpp"
#include "ws_client/BufferedSocketAsync.hpp"
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
using namespace std::chrono_literals;

/**
 * Web socket client class with non-blocking async I/O operations based
 * on C++20 coroutines. Customizable templated socket, mask key generator types
 * and coroutine task type.
 * 
 * The `close()` method for closing the underlying socket connection
 * is not called automatically. It is the responsibility of the caller
 * to close the connection when it is no longer needed or in case of
 * errors. The caller MUST close the client upon receiving a close frame
 * or an error, read or write operations afterwards are undefined behaviour.
 * 
 * @tparam TLogger       Logger type for logging messages and errors.
 *
 * @tparam TSocket       Socket implementation type for transportation.
 *                       Must implement contract `HasSocketOperationsAsync`.
 * 
 *                       Available 3rd-party I/O bindings:
 *                       - `CoroioSocket`, for non-blocking async I/O based on `coroio`
 *                       - `AsioSocket`, for non-blocking async I/O based on `asio`
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
    template <typename...> typename TTask,
    typename TLogger,
    typename TSocket,
    typename TMaskKeyGen = DefaultMaskKeyGen>
    requires HasSocketOperationsAsync<TSocket, TTask> && HasMaskKeyOperator<TMaskKeyGen>
class WebSocketClientAsync
{
private:
    bool closed_ = true;

    BufferedSocketAsync<TSocket, TTask> socket_;
    TLogger* logger_;

    // mask key generator
    TMaskKeyGen mask_key_gen_;

    // negotiation handshake
    optional<PermessageDeflateContext<TLogger>> permessage_deflate_ctx_ = std::nullopt;

    // buffers for header data and control frame payloads
    alignas(64) array<byte, 128> write_buffer_storage_;
    span<byte> write_buffer = span(write_buffer_storage_);

    alignas(64) array<byte, 128> read_buffer_storage_;
    span<byte> read_buffer = span(read_buffer_storage_);

    // maintain state for reading messages (might get interrupted with control frames, which require immediate handling)
    MessageReadState read_state_;

    // permessage-deflate buffers
    Buffer decompress_buffer_;
    Buffer compress_buffer_;

public:
    explicit WebSocketClientAsync(
        TLogger* logger, TSocket&& socket, TMaskKeyGen&& mask_key_generator
    ) noexcept
        : socket_(BufferedSocket(std::move(socket))),
          logger_(logger),
          mask_key_gen_(mask_key_generator)
    {
    }

    explicit WebSocketClientAsync(TLogger* logger, TSocket&& socket) noexcept
        : socket_(BufferedSocketAsync<TSocket, TTask>(std::move(socket))),
          logger_(logger),
          mask_key_gen_(DefaultMaskKeyGen())
    {
    }

    // disable copying
    WebSocketClientAsync(const WebSocketClientAsync&) = delete;
    WebSocketClientAsync& operator=(WebSocketClientAsync const&) = delete;

    // enable move
    WebSocketClientAsync(WebSocketClientAsync&& other) noexcept
        : closed_(other.closed_),
          socket_(other.socket_),
          logger_(other.logger_),
          mask_key_gen_(std::move(other.mask_key_gen_)),
          permessage_deflate_ctx_(std::move(other.permessage_deflate_ctx_)),
          read_state_(other.read_state_),
          decompress_buffer_(std::move(other.decompress_buffer_)),
          compress_buffer_(std::move(other.compress_buffer_))
    {
        this->write_buffer_storage_ = std::move(other.write_buffer_storage_);
        this->write_buffer = span(this->write_buffer_storage_);
        this->read_buffer_storage_ = std::move(other.read_buffer_storage_);
        this->read_buffer = span(this->read_buffer_storage_);
    }
    WebSocketClientAsync& operator=(WebSocketClientAsync&& other) noexcept
    {
        if (this != &other)
        {
            this->closed_ = other.closed_;
            this->socket_ = other.socket_;
            this->logger_ = other.logger_;
            this->mask_key_gen_ = std::move(other.mask_key_gen_);
            this->permessage_deflate_ctx_ = std::move(other.permessage_deflate_ctx_);
            this->write_buffer_storage_ = std::move(other.write_buffer_storage_);
            this->write_buffer = span(this->write_buffer_storage_);
            this->read_buffer_storage_ = std::move(other.read_buffer_storage_);
            this->read_buffer = span(this->read_buffer_storage_);
            this->read_state_ = other.read_state_;
            this->decompress_buffer_ = std::move(other.decompress_buffer_);
            this->compress_buffer_ = std::move(other.compress_buffer_);
        }
        return *this;
    }

    [[nodiscard]] inline BufferedSocketAsync<TSocket, TTask>& underlying() noexcept
    {
        return this->socket_;
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
        return !this->closed_;
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
        return this->closed_;
    }

    /**
     * Performs the WebSocket handshake using a HTTP request,
     * which should result in a connection upgrade to a WebSocket connection.
     * 
     * Compression parameters are negotiated during the handshake (permessage-deflate extension).
     * 
     * Messages can be sent and received after this method returns successfully.
     * 
     * User needs to ensure this method is called only once.
     */
    [[nodiscard]] TTask<expected<void, WSError>> handshake(
        Handshake<TLogger>& handshake, std::chrono::milliseconds timeout_ms = 5000ms
    )
    {
        if (!this->closed_)
            co_return WS_ERROR(logic_error, "Connection already open.", close_code::not_set);

        Timeout timeout(timeout_ms);

        // send HTTP request for websocket upgrade
        auto req_str = handshake.get_request_message();
        span<byte> req_data = span(reinterpret_cast<byte*>(req_str.data()), req_str.size());
        WS_CO_TRYV(co_await this->socket_.write(req_data, timeout));

        // read HTTP response
        Buffer headers_buffer;
        byte delim[4] = {byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
        span<byte> delim_span = span(delim);
        WS_CO_TRYV(co_await this->socket_.read_until(headers_buffer, delim_span, timeout));

        // read and discard header terminator bytes \r\n\r\n
        WS_CO_TRYV(co_await this->socket_.read_exact(delim_span, timeout));

        // process HTTP response
        WS_CO_TRYV(handshake.process_response(string_from_bytes(headers_buffer.data())));

        // initialize permessage-deflate compression if negotiated
        if (handshake.is_compression_negotiated())
        {
            auto& permessage_deflate = handshake.get_permessage_deflate();
            this->permessage_deflate_ctx_.emplace(logger_, permessage_deflate);
            WS_CO_TRYV(this->permessage_deflate_ctx_->init());

            // allocate buffers
            this->decompress_buffer_.set_max_size(permessage_deflate.decompress_buffer_size);
            this->compress_buffer_.set_max_size(permessage_deflate.compress_buffer_size);
            WS_CO_TRYV(this->decompress_buffer_.reserve(1024)); // reserve 1 KB initial size
            WS_CO_TRYV(this->compress_buffer_.reserve(1024));   // reserve 1 KB initial size
        }

        this->closed_ = false;

        co_return expected<void, WSError>{};
    }

    /**
     * Reads a message from the WebSocket connection.
     * The message is read into the provided buffer, which must have enough space to hold the message.
     * 
     * This method waits until a message is received, the timeout expires, or an error occurs.
     * 
     * Upon receiving any error, the connection must be closed using `close()` method, this includes timeouts.
     */
    template <HasBufferOperations TBuffer>
    [[nodiscard]] TTask<variant<Message, PingFrame, PongFrame, CloseFrame, WSError>> read_message(
        TBuffer& buffer, std::chrono::milliseconds timeout_ms
    ) noexcept
    {
        if (this->closed_)
            co_return WSError(WSErrorCode::connection_closed, "Connection in closed state.");

        Timeout timeout(timeout_ms);

        while (!timeout.is_expired())
        {
            // read next frame w/o payload
            WS_CO_TRY_RAW(frame_res, co_await this->read_frame(timeout));
            Frame& frame = *frame_res;

            // check reserved opcodes
            if (is_reserved(frame.header.op_code()))
            {
                co_return WSError(
                    WSErrorCode::protocol_error,
                    "Reserved opcode received: " + to_string(frame.header.op_code()),
                    close_code::protocol_error
                );
            }

            // handle control frames
            if (frame.header.is_control())
            {
                auto res = co_await this->handle_control_frame(frame, timeout);

                // convert to outer variant
                co_return std::visit(
                    [](auto&& arg) //
                    -> variant<Message, PingFrame, PongFrame, CloseFrame, WSError> { return arg; },
                    res
                );
            }

            if (read_state_.is_first)
            {
                // clear buffer if this is the first frame
                buffer.clear();
            }

            // check if payload fits into buffer
            if (buffer.max_size() - buffer.size() < frame.payload_size) [[unlikely]]
            {
                string msg = "Received message payload of " + std::to_string(frame.payload_size) +
                             " bytes is too large, only " +
                             std::to_string(buffer.max_size() - buffer.size()) +
                             " bytes available.";
                co_return WSError(WSErrorCode::buffer_error, msg, close_code::message_too_big);
            }

            // check if this is the first frame
            if (read_state_.is_first)
            {
                read_state_.is_first = false;
                read_state_.op_code = frame.header.op_code();

                // RSV1 indicates DEFLATE compressed message, only if negotiated.
                if (frame.header.rsv1_bit())
                {
                    read_state_.is_compressed = true;

                    if (this->permessage_deflate_ctx_ != std::nullopt) [[likely]]
                    {
                        this->decompress_buffer_.clear();
                    }
                    else
                    {
                        co_return WSError(
                            WSErrorCode::protocol_error,
                            "Received compressed frame, but compression not enabled.",
                            close_code::protocol_error
                        );
                    }
                }

                if (frame.header.rsv2_bit() || frame.header.rsv3_bit()) [[unlikely]]
                {
                    co_return WSError(
                        WSErrorCode::protocol_error,
                        "RSV2 or rsv3 bit set, but not supported.",
                        close_code::protocol_error
                    );
                }
            }
            else
            {
                if (frame.header.op_code() != opcode::continuation) [[unlikely]]
                {
                    co_return WSError(
                        WSErrorCode::protocol_error,
                        "Expected continuation frame, but received " +
                            to_string(frame.header.op_code()),
                        close_code::protocol_error
                    );
                }

                if (frame.header.has_rsv_bits()) [[unlikely]]
                {
                    co_return WSError(
                        WSErrorCode::protocol_error,
                        "RSV bits must not be set on non-first frames.",
                        close_code::protocol_error
                    );
                }
            }

            // check opcode
            if (read_state_.op_code != opcode::continuation &&
                read_state_.op_code != opcode::text && read_state_.op_code != opcode::binary)
            {
                co_return WSError(
                    WSErrorCode::protocol_error,
                    "Unexpected opcode in websocket frame received: " +
                        to_string(read_state_.op_code),
                    close_code::protocol_error
                );
            }

            // read payload
            if (frame.payload_size > 0) [[likely]]
            {
                if (read_state_.is_compressed)
                {
                    // read payload into decompression buffer
                    WS_CO_TRY_RAW(
                        frame_data_compressed_res,
                        this->decompress_buffer_.append(frame.payload_size)
                    );
                    WS_CO_TRYV_RAW(
                        co_await this->socket_.read_exact(*frame_data_compressed_res, timeout)
                    );
                }
                else
                {
                    // read payload into message buffer
                    WS_CO_TRY_RAW(frame_data_res, buffer.append(frame.payload_size));
                    WS_CO_TRYV_RAW(co_await this->socket_.read_exact(*frame_data_res, timeout));
                }
            }

            if (frame.header.is_final()) [[likely]]
                break;
        }

        // check if timeout occurred
        if (timeout.is_expired())
            co_return WSError(WSErrorCode::timeout, "Timeout while reading message.");

        span<byte> payload_buffer;

        // handle permessage-deflate compression
        if (read_state_.is_compressed)
        {
            span<byte> input = this->decompress_buffer_.data();
            WS_CO_TRYV_RAW(this->permessage_deflate_ctx_.value().decompress(input, buffer));
            payload_buffer = buffer.data();
        }
        else
        {
            payload_buffer = buffer.data();
        }

        switch (read_state_.op_code)
        {
            case opcode::text:
            {
#if WS_CLIENT_VALIDATE_UTF8 == 1
                if (!is_valid_utf8(
                        const_cast<char*>((char*)payload_buffer.data()), payload_buffer.size()
                    ))
                {
                    co_return WSError(
                        WSErrorCode::protocol_error,
                        "Invalid UTF-8 in websocket text message.",
                        close_code::invalid_frame_payload_data
                    );
                }
#endif

                if (logger_->template is_enabled<LogLevel::I>())
                {
#if WS_CLIENT_LOG_MSG_PAYLOADS == 1
                    std::stringstream ss;
                    ss << "Received text message (";
                    ss << payload_buffer.size();
                    ss << " bytes):\033[1;35m\n";
                    ss << string(
                        reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                    );
                    ss << "\033[0m";
                    logger_->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES == 1
                    logger_->template log(
                        LogLevel::I, "Received text message (", payload_buffer.size(), " bytes)"
                    );
#endif
                }

                auto msg = Message(static_cast<MessageType>(read_state_.op_code), payload_buffer);

                // reset reading state - message complete
                read_state_.reset();

                co_return msg;
            }

            case opcode::binary:
            {
                if (logger_->template is_enabled<LogLevel::I>())
                {
#if WS_CLIENT_LOG_MSG_PAYLOADS == 1
                    std::stringstream ss;
                    ss << "Received binary message (";
                    ss << payload_buffer.size();
                    ss << " bytes):\033[1;35m\n";
                    ss << string(
                        reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                    );
                    ss << "\033[0m";
                    logger_->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES == 1
                    logger_->template log(
                        LogLevel::I,
                        "Received binary message (" + std::to_string(payload_buffer.size()) +
                            " bytes)"
                    );
#endif
                }

                auto msg = Message(static_cast<MessageType>(read_state_.op_code), payload_buffer);

                // reset reading state - message complete
                read_state_.reset();

                co_return msg;
            }

            default:
            {
                co_return WSError(
                    WSErrorCode::protocol_error,
                    "Unexpected opcode frame received: " + to_string(read_state_.op_code),
                    close_code::protocol_error
                );
            }
        }
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_message(
        const Message& msg, SendOptions options = {}
    ) noexcept
    {
        if (this->closed_)
        {
            co_return WS_ERROR(
                connection_closed, "Connection in closed state.", close_code::not_set
            );
        }

        if (logger_->template is_enabled<LogLevel::I>()) [[unlikely]]
        {
#if WS_CLIENT_LOG_MSG_PAYLOADS == 1
            std::stringstream ss;
            ss << "Writing ";
            ss << to_string(msg.type);
            ss << " message (";
            ss << msg.data.size();
            ss << " bytes):\033[1;34m\n";
            ss << msg.to_string_view();
            ss << "\033[0m";
            logger_->template log<LogLevel::I>(ss.str());
#elif WS_CLIENT_LOG_MSG_SIZES == 1
            logger_->template log<LogLevel::I>(
                "Writing " + to_string(msg.type) + " message (" + std::to_string(msg.data.size()) +
                " bytes)"
            );
#endif
        }

        Frame frame;
        frame.set_opcode(static_cast<opcode>(msg.type));
        frame.set_is_final(true); // TODO: support fragmented messages
        frame.set_is_masked(true);
        frame.mask_key = this->mask_key_gen_();

        span<byte> payload;
        if (this->permessage_deflate_ctx_ != std::nullopt && options.compress)
        {
            frame.set_is_compressed(true);

            // perform deflate compression using zlib
            Buffer& output = this->compress_buffer_;
            output.clear();
            WS_CO_TRY(res, this->permessage_deflate_ctx_.value().compress(msg.data, output));
            payload = *res;
        }
        else
            payload = msg.data;

        frame.set_payload_size(payload.size());

        Timeout timeout(options.timeout);
        WS_CO_TRYV(co_await this->write_frame(frame, payload, timeout));

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_pong_frame(
        span<byte> payload, std::chrono::milliseconds timeout_ms = 5000ms
    ) noexcept
    {
        if (this->closed_)
        {
            co_return WS_ERROR(
                connection_closed, "Connection in closed state.", close_code::not_set
            );
        }

        Frame frame;
        frame.set_opcode(opcode::pong);
        frame.set_is_final(true);
        frame.set_is_masked(true); // write_frame does the actual masking
        frame.set_payload_size(payload.size());
        frame.mask_key = this->mask_key_gen_();

        Timeout timeout(timeout_ms);
        WS_CO_TRYV(co_await this->write_frame(frame, payload, timeout));

        co_return expected<void, WSError>{};
    }

    /**
     * Closes the WebSocket connection.
     * 
     * This method sends a close frame to the server and waits for the server,
     * shuts down the socket communication and closes the underlying socket connection.
     */
    [[nodiscard]] inline TTask<expected<void, WSError>> close(
        const close_code code, std::chrono::milliseconds timeout_ms = 5000ms
    )
    {
        if (this->closed_)
            co_return expected<void, WSError>{};

        Timeout timeout(timeout_ms);

        // send close frame
        {
            auto res = co_await this->send_close_frame(code, timeout);
            if (!res.has_value())
            {
                logger_->template log<LogLevel::W>(
                    "Failed to send close frame: " + res.error().message
                );
            }
        }

        // mark as closed
        this->closed_ = true;

        // shutdown socket communication (ignore errors, close socket anyway).
        // often times, the server will close the connection after receiving the close frame,
        // which will result in an error when trying to shutdown the socket.
        co_await this->socket_.underlying().shutdown(timeout);

        // close underlying socket connection
        {
            auto res = co_await this->socket_.underlying().close();
            if (!res.has_value())
            {
                logger_->template log<LogLevel::W>("Socket close failed: " + res.error().message);
                co_return std::unexpected(res.error());
            }
        }

        co_return expected<void, WSError>{};
    }

private:
    [[nodiscard]] TTask<expected<Frame, WSError>> read_frame(Timeout<>& timeout)
    {
        Frame frame;

        // read frame header (2 bytes)
        byte tmp1[2];
        WS_CO_TRYV(co_await this->socket_.read_exact(span<byte>(tmp1, 2), timeout));

        frame.header.b0 = tmp1[0];
        frame.header.b1 = tmp1[1];

        if (!frame.header.is_final() && frame.header.op_code() == opcode::close) [[unlikely]]
        {
            co_return WS_ERROR(
                protocol_error, "Received fragmented close frame.", close_code::protocol_error
            );
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
            WS_CO_TRYV(co_await this->socket_.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp2), sizeof(uint16_t)), timeout
            ));
            payload_size = network_to_host(tmp2);
        }
        else
        {
            // 64 bit payload size
            uint64_t tmp3;
            WS_CO_TRYV(co_await this->socket_.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp3), sizeof(uint64_t)), timeout
            ));
            payload_size = network_to_host(tmp3);
        }

        frame.payload_size = payload_size;

        // verify not masked
        if (frame.header.is_masked()) [[unlikely]]
        {
            co_return WS_ERROR(
                protocol_error, "Received masked frame from server.", close_code::protocol_error
            );
        }

        if (logger_->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
#if WS_CLIENT_LOG_FRAMES == 1
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
            logger_->template log<LogLevel::D>(msg.str());
#endif
        }

        co_return frame;
    }

    [[nodiscard]] TTask<expected<void, WSError>> write_frame(
        Frame& frame, span<byte> payload, Timeout<>& timeout
    ) noexcept
    {
        if (logger_->template is_enabled<LogLevel::D>())
        {
#if WS_CLIENT_LOG_FRAMES == 1
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
            logger_->template log<LogLevel::D>(msg.str());
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
        {
            co_return WS_ERROR(
                protocol_error, "Frame sent by client MUST be masked.", close_code::protocol_error
            );
        }

        // write 4 byte masking key
        std::memcpy(&write_buffer[offset], &frame.mask_key.key, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // mask payload in-place
        frame.mask_key.mask(payload);

        // write frame header
        WS_CO_TRYV(co_await this->socket_.write(write_buffer.subspan(0, offset), timeout));

        // write frame payload
        if (frame.payload_size > 0)
        {
            WS_CO_TRYV(co_await this->socket_.write(payload, timeout));
            offset += frame.payload_size;
        }

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<expected<void, WSError>> send_close_frame(
        close_code code, Timeout<>& timeout
    ) noexcept
    {
        Frame frame;
        frame.set_opcode(opcode::close);
        frame.set_is_final(true);
        frame.set_is_masked(true);
        frame.mask_key = this->mask_key_gen_();

        span<byte> payload;

        if (code != close_code::not_set)
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
            logger_->template log<LogLevel::I>(msg.str());
        }
        else
        {
            // close frame without status code
            logger_->template log<LogLevel::I>("Writing close frame");
        }

        frame.set_payload_size(payload.size());

        WS_CO_TRY(ret, co_await this->write_frame(frame, payload, timeout));

        logger_->template log<LogLevel::D>("Close frame sent");

        co_return expected<void, WSError>{};
    }

    [[nodiscard]] TTask<variant<PingFrame, PongFrame, CloseFrame, WSError>> handle_control_frame(
        Frame& frame, Timeout<>& timeout
    ) noexcept
    {
        if (!frame.header.is_final())
        {
            co_return WSError(
                WSErrorCode::protocol_error,
                "Received fragmented control frame.",
                close_code::protocol_error
            );
        }

        if (frame.header.has_rsv_bits())
        {
            co_return WSError(
                WSErrorCode::protocol_error,
                "Invalid RSV bits found in control frame.",
                close_code::protocol_error
            );
        }

        if (frame.payload_size > 125)
        {
            co_return WSError(
                WSErrorCode::protocol_error,
                "Control frame payload size larger than 125 bytes, got " +
                    std::to_string(frame.payload_size),
                close_code::protocol_error
            );
        }

        switch (frame.header.op_code())
        {
            case opcode::close:
            {
                if (!this->closed_)
                {
                    // close frame sent by server
                    logger_->template log<LogLevel::W>("Unsolicited close frame received");
                }

                CloseFrame close_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    if (frame.payload_size == 1)
                    {
                        co_return WSError(
                            WSErrorCode::protocol_error,
                            "Invalid close frame payload size of 1.",
                            close_code::protocol_error
                        );
                    }

                    WS_CO_TRYV_RAW(
                        co_await this->socket_.read_exact(close_frame.payload_bytes(), timeout)
                    );

                    // check close code if provided
                    if (close_frame.has_close_code())
                    {
                        auto code = close_frame.get_close_code();
                        if (!is_valid_close_code(code))
                        {
                            co_return WSError(
                                WSErrorCode::protocol_error,
                                "Invalid close code " + std::to_string(static_cast<uint16_t>(code)),
                                close_code::protocol_error
                            );
                        }
                    }

#if WS_CLIENT_VALIDATE_UTF8 == 1
                    // check close reason string is valid UTF-8 string
                    if (!close_frame.is_reason_valid_utf8())
                    {
                        co_return WSError(
                            WSErrorCode::protocol_error,
                            "Invalid UTF-8 in websocket close reason string.",
                            close_code::invalid_frame_payload_data
                        );
                    }
#endif
                }

                co_return close_frame;
            }

            case opcode::ping:
            {
                PingFrame ping_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_CO_TRYV_RAW(
                        co_await this->socket_.read_exact(ping_frame.payload_bytes(), timeout)
                    );
                }

                co_return ping_frame;
            }

            case opcode::pong:
            {
                PongFrame pong_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_CO_TRYV_RAW(
                        co_await this->socket_.read_exact(pong_frame.payload_bytes(), timeout)
                    );
                }

                co_return pong_frame;
            }

            default:
            {
                co_return WSError(
                    WSErrorCode::protocol_error,
                    "Unexpected opcode for websocket control frame received: " +
                        to_string(frame.header.op_code()),
                    close_code::protocol_error
                );
            }
        }
    }
};
} // namespace ws_client