#pragma once

#include <string>
#include <format>
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
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/transport/HasSocketOperations.hpp"
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
using namespace std::chrono_literals;

/**
 * Web socket client class with blocking I/O operations and
 * customizable, templated socket and mask key generator types.
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
 *                       Must implement contract `HasSocketOperations`.
 * 
 *                       Blocking I/O built-in implementations:
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
    bool closed_ = true;

    BufferedSocket<TSocket> socket_;
    TLogger* logger_;

    // mask key generator
    TMaskKeyGen mask_key_gen_;

    // negotiation handshake
    optional<PermessageDeflateContext<TLogger>> permessage_deflate_ctx_ = std::nullopt;

    // buffers for header data and control frame payloads
    alignas(64) array<byte, 128> write_buffer_storage_;
    span<byte> write_buffer_ = span(write_buffer_storage_);

    alignas(64) array<byte, 128> read_buffer_storage_;
    span<byte> read_buffer_ = span(read_buffer_storage_);

    // maintain state for reading messages.
    // message reading might get interrupted with control frames,
    // which require immediate handling.
    MessageReadState read_state_;

public:
    explicit WebSocketClient(
        TLogger* logger, TSocket&& socket, TMaskKeyGen&& mask_key_generator
    ) noexcept
        : socket_(BufferedSocket(std::move(socket))),
          logger_(logger),
          mask_key_gen_(mask_key_generator)
    {
    }

    explicit WebSocketClient(TLogger* logger, TSocket&& socket) noexcept
        : socket_(BufferedSocket(std::move(socket))),
          logger_(logger),
          mask_key_gen_(DefaultMaskKeyGen())
    {
    }

    // disable copying
    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(WebSocketClient const&) = delete;

    // enable move
    WebSocketClient(WebSocketClient&& other) noexcept
        : closed_(other.closed_),
          socket_(other.socket_),
          logger_(other.logger_),
          mask_key_gen_(std::move(other.mask_key_gen_)),
          permessage_deflate_ctx_(std::move(other.permessage_deflate_ctx_)),
          read_state_(other.read_state_)
    {
        this->write_buffer_storage_ = std::move(other.write_buffer_storage_);
        this->write_buffer_ = span(this->write_buffer_storage_);
        this->read_buffer_storage_ = std::move(other.read_buffer_storage_);
        this->read_buffer_ = span(this->read_buffer_storage_);
    }
    WebSocketClient& operator=(WebSocketClient&& other) noexcept
    {
        if (this != &other)
        {
            this->closed_ = other.closed_;
            this->socket_ = other.socket_;
            this->logger_ = other.logger_;
            this->mask_key_gen_ = std::move(other.mask_key_gen_);
            this->permessage_deflate_ctx_ = std::move(other.permessage_deflate_ctx_);
            this->write_buffer_storage_ = std::move(other.write_buffer_storage_);
            this->write_buffer_ = span(this->write_buffer_storage_);
            this->read_buffer_storage_ = std::move(other.read_buffer_storage_);
            this->read_buffer_ = span(this->read_buffer_storage_);
            this->read_state_ = other.read_state_;
        }
        return *this;
    }

    /**
     * Returns the underlying socket object.
     */
    [[nodiscard]] inline BufferedSocket<TSocket>& underlying() noexcept
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
    [[nodiscard]] expected<void, WSError> handshake(
        Handshake<TLogger>& handshake, std::chrono::milliseconds timeout_ms = 5s
    ) noexcept
    {
        if (!this->closed_)
            return WS_ERROR(logic_error, "Connection already open.", close_code::not_set);

        Timeout timeout(timeout_ms);

        // send HTTP request for websocket upgrade
        auto req_str = handshake.get_request_message();
        span<byte> req_data = span(reinterpret_cast<byte*>(req_str.data()), req_str.size());
        WS_TRYV(socket_.write(req_data, timeout));

        // read HTTP response
        WS_TRY(headers_buffer, Buffer::create(1024, 1024 * 1024)); // 1 KB to 1 MB
        byte delim[4] = {byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
        span<byte> delim_span = span(delim);
        WS_TRYV(socket_.read_until(*headers_buffer, delim_span, timeout));

        // read and discard header terminator bytes \r\n\r\n
        WS_TRYV(socket_.read_exact(delim_span, timeout));

        // process HTTP response
        WS_TRYV(handshake.process_response(string_from_bytes(headers_buffer->data())));

        // initialize permessage-deflate compression if negotiated
        if (handshake.is_compression_negotiated())
        {
            auto& permessage_deflate = handshake.get_permessage_deflate();
            this->permessage_deflate_ctx_.emplace(logger_, permessage_deflate);
            WS_TRYV(this->permessage_deflate_ctx_->init());
        }

        this->closed_ = false;

        return expected<void, WSError>{};
    }

    /**
     * Waits until a message is available to read from the WebSocket connection.
     * Note that this includes control frames like PING, PONG, and CLOSE frames.
     * 
     * Note that the timeout does not cause an error, but returns `false` if it expires.
     * 
     * @returns `true` if a message is available to read, `false` if timeout expires.
     */
    [[nodiscard]] inline expected<bool, WSError> wait_message(
        std::chrono::milliseconds timeout_ms
    ) noexcept
    {
        if (this->closed_)
            return WS_ERROR(connection_closed, "Connection in closed state.", close_code::not_set);

        Timeout timeout(timeout_ms);

        return this->socket_.wait_readable(timeout);
    }

    /**
     * Reads a message from the WebSocket connection.
     * The message is read into the provided buffer, which must have enough space to hold the message.
     * 
     * This method blocks until a message is received, the timeout expires, or an error occurs.
     * 
     * Upon receiving any error, the connection must be closed using `close()` method, this includes timeouts.
     */
    template <HasBufferOperations TBuffer>
    [[nodiscard]] variant<Message, PingFrame, PongFrame, CloseFrame, WSError> read_message(
        TBuffer& buffer, std::chrono::milliseconds timeout_ms
    ) noexcept
    {
        if (this->closed_)
            return WSError(WSErrorCode::connection_closed, "Connection in closed state.");

        Timeout timeout(timeout_ms);

        while (!timeout.is_expired())
        {
            // read next frame w/o payload
            WS_TRY_RAW(frame_res, this->read_frame(timeout));
            Frame& frame = *frame_res;

            // check reserved opcodes
            if (is_reserved(frame.header.op_code()))
            {
                return WSError(
                    WSErrorCode::protocol_error,
                    std::format("Reserved opcode received: {}", to_string(frame.header.op_code())),
                    close_code::protocol_error
                );
            }

            // handle control frames
            if (frame.header.is_control())
            {
                auto res = this->handle_control_frame(frame, timeout);

                // convert to outer variant
                return std::visit(
                    [](auto&& arg) //
                    -> variant<Message, PingFrame, PongFrame, CloseFrame, WSError> { return arg; },
                    res
                );
            }

            if (read_state_.is_first) [[likely]]
            {
                // clear buffer if this is the first frame
                buffer.clear();
            }

            // check if payload fits into buffer
            if (buffer.max_size() - buffer.size() < frame.payload_size) [[unlikely]]
            {
                return WSError(
                    WSErrorCode::buffer_error,
                    std::format(
                        "Received message payload of {} bytes is too large, only {} bytes "
                        "available.",
                        frame.payload_size,
                        buffer.max_size() - buffer.size()
                    ),
                    close_code::message_too_big
                );
            }

            // check if this is the first frame
            if (read_state_.is_first)
            {
                read_state_.is_first = false;
                read_state_.op_code = frame.header.op_code();

                // RSV1 indicates DEFLATE compressed message, but only if negotiated.
                if (frame.header.rsv1_bit())
                {
                    read_state_.is_compressed = true;

                    if (this->permessage_deflate_ctx_ != std::nullopt) [[likely]]
                    {
                        this->permessage_deflate_ctx_->decompress_buffer().clear();
                    }
                    else
                    {
                        return WSError(
                            WSErrorCode::protocol_error,
                            "Received compressed frame, but compression not enabled.",
                            close_code::protocol_error
                        );
                    }
                }

                if (frame.header.rsv2_bit() || frame.header.rsv3_bit()) [[unlikely]]
                {
                    return WSError(
                        WSErrorCode::protocol_error,
                        "RSV2 or RSV3 bit set, but not supported.",
                        close_code::protocol_error
                    );
                }
            }
            else
            {
                if (frame.header.op_code() != opcode::continuation) [[unlikely]]
                {
                    return WSError(
                        WSErrorCode::protocol_error,
                        std::move(string("Expected continuation frame, but received ")
                                      .append(to_string(frame.header.op_code()))),
                        close_code::protocol_error
                    );
                }

                if (frame.header.has_rsv_bits()) [[unlikely]]
                {
                    return WSError(
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
                return WSError(
                    WSErrorCode::protocol_error,
                    std::move(string("Unexpected opcode in websocket frame received: ")
                                  .append(to_string(read_state_.op_code))),
                    close_code::protocol_error
                );
            }

            // read payload
            if (frame.payload_size > 0) [[likely]]
            {
                if (read_state_.is_compressed)
                {
                    // read payload directly into decompression buffer
                    WS_TRY_RAW(
                        frame_data_compressed_res,
                        this->permessage_deflate_ctx_->decompress_buffer().append(frame.payload_size
                        )
                    );
                    WS_TRYV_RAW(this->socket_.read_exact(*frame_data_compressed_res, timeout));
                }
                else
                {
                    // read payload into message buffer
                    WS_TRY_RAW(frame_data_res, buffer.append(frame.payload_size));
                    WS_TRYV_RAW(this->socket_.read_exact(*frame_data_res, timeout));
                }
            }

            if (frame.header.is_final()) [[likely]]
                break;
        }

        // check if timeout occurred
        if (timeout.is_expired())
            return WSError(WSErrorCode::timeout_error, "Timeout while reading WebSocket message.");

        span<byte> payload_buffer;

        // handle permessage-deflate compression
        if (read_state_.is_compressed)
        {
            WS_TRYV_RAW(this->permessage_deflate_ctx_.value().decompress(buffer));
        }

        payload_buffer = buffer.data();

        switch (read_state_.op_code)
        {
            case opcode::text:
            {
#if WS_CLIENT_VALIDATE_UTF8 == 1
                if (!is_valid_utf8(
                        const_cast<char*>((char*)payload_buffer.data()), payload_buffer.size()
                    ))
                {
                    return WSError(
                        WSErrorCode::protocol_error,
                        "Invalid UTF-8 in websocket TEXT message.",
                        close_code::invalid_frame_payload_data
                    );
                }
#endif

#if WS_CLIENT_LOG_RECV_FRAME > 0
                if (logger_->template is_enabled<LogLevel::I, LogTopic::RecvFrame>())
                {
                    logger_->template log<LogLevel::I, LogTopic::RecvFrame>(
                        std::format("Received TEXT message with {} bytes", payload_buffer.size())
                    );
                }
#endif

#if WS_CLIENT_LOG_RECV_FRAME_PAYLOAD > 0
                if (logger_->template is_enabled<LogLevel::I, LogTopic::RecvFramePayload>())
                {
                    logger_->template log<LogLevel::I, LogTopic::RecvFramePayload>(std::format(
                        "Message payload:\033[1;35m\n{}\033[0m",
                        std::string_view(
                            reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                        )
                    ));
                }
#endif

                auto msg = Message(static_cast<MessageType>(read_state_.op_code), payload_buffer);

                // reset reading state - message complete
                read_state_.reset();

                return msg;
            }

            case opcode::binary:
            {
#if WS_CLIENT_LOG_RECV_FRAME > 0
                if (logger_->template is_enabled<LogLevel::I, LogTopic::RecvFrame>())
                {
                    logger_->template log<LogLevel::I, LogTopic::RecvFrame>(
                        std::format("Received BINARY message with {} bytes", payload_buffer.size())
                    );
                }
#endif

#if WS_CLIENT_LOG_RECV_FRAME_PAYLOAD > 0
                if (logger_->template is_enabled<LogLevel::I, LogTopic::RecvFramePayload>())
                {
                    logger_->template log<LogLevel::I, LogTopic::RecvFramePayload>(std::format(
                        "Message payload:\033[1;35m\n{}\033[0m",
                        std::string_view(
                            reinterpret_cast<char*>(payload_buffer.data()), payload_buffer.size()
                        )
                    ));
                }
#endif

                auto msg = Message(static_cast<MessageType>(read_state_.op_code), payload_buffer);

                // reset reading state - message complete
                read_state_.reset();

                return msg;
            }

            default:
            {
                return WSError(
                    WSErrorCode::protocol_error,
                    std::format(
                        "Unexpected opcode frame received: {}", to_string(read_state_.op_code)
                    ),
                    close_code::protocol_error
                );
            }
        }
    }

    /**
     * Sends a message to the WebSocket server.
     * 
     * Compression and send timeout can be configured using the `SendOptions` struct.
     * 
     * NOTE: The message is always sent as a single frame, fragmentation is currently not supported.
     */
    [[nodiscard]] expected<void, WSError> send_message(
        const Message& msg, SendOptions options = {}
    ) noexcept
    {
        if (this->closed_)
            return WS_ERROR(connection_closed, "Connection in closed state.", close_code::not_set);

#if WS_CLIENT_LOG_SEND_FRAME > 0
        if (logger_->template is_enabled<LogLevel::I, LogTopic::SendFrame>()) [[unlikely]]
        {
            logger_->template log<LogLevel::I, LogTopic::SendFrame>(std::format(
                "Writing {} message with {} bytes", to_string(msg.type), msg.data.size()
            ));
        }
#endif

#if WS_CLIENT_LOG_SEND_FRAME_PAYLOAD > 0
        if (logger_->template is_enabled<LogLevel::I, LogTopic::SendFramePayload>()) [[unlikely]]
        {
            logger_->template log<LogLevel::I, LogTopic::SendFramePayload>(
                std::format("Message payload:\033[1;34m\n{}\033[0m", msg.to_string_view())
            );
        }
#endif

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
            this->permessage_deflate_ctx_->compress_buffer().clear();
            WS_TRY(res, this->permessage_deflate_ctx_->compress(msg.data));
            payload = *res;
        }
        else
            payload = msg.data;

        frame.set_payload_size(payload.size());

        Timeout timeout(options.timeout);
        WS_TRYV(this->write_frame(frame, payload, timeout));

        return expected<void, WSError>{};
    }

    /**
     * Sends a PONG frame to the server in response to a PING frame.
     */
    [[nodiscard]] expected<void, WSError> send_pong_frame(
        span<byte> payload, std::chrono::milliseconds timeout_ms = 5s
    ) noexcept
    {
        if (this->closed_)
            return WS_ERROR(connection_closed, "Connection in closed state.", close_code::not_set);

        Frame frame;
        frame.set_opcode(opcode::pong);
        frame.set_is_final(true);
        frame.set_is_masked(true); // write_frame does the actual masking
        frame.set_payload_size(payload.size());
        frame.mask_key = this->mask_key_gen_();

        Timeout timeout(timeout_ms);
        WS_TRYV(this->write_frame(frame, payload, timeout));

        return expected<void, WSError>{};
    }

    /**
     * Closes the WebSocket connection.
     * 
     * This method sends a `CLOSE` frame to the server,
     * shuts down the socket communication, and closes the underlying socket connection.
     * 
     * Under a normal closure, the client sends a `CLOSE` frame to the server,
     * and performs a graceful shutdown of the connection before closing the socket.
     * 
     * If the client has to fail the connection, is immediately closes the connection
     * without sending a `CLOSE` frame or performing a graceful shutdown.
     * 
     * The following `ws_client::close_code` codes result in a connection failure:
     * - 1002 protocol_error
     * - 1003 unacceptable_data_type
     * - 1007 invalid_frame_payload_data
     * - 1008 policy_violation
     * - 1009 message_too_big
     * - 1010 missing_extension
     * - 1011 unexpected_condition
     * 
     * This method can be called multiple times.
     * 
     * References:
     * - https://www.rfc-editor.org/rfc/rfc6455#section-7.1.7
     */
    [[nodiscard]] inline expected<void, WSError> close(
        close_code code, std::chrono::milliseconds timeout_ms = 5s
    ) noexcept
    {
        if (this->closed_)
            return expected<void, WSError>{};

        Timeout timeout(timeout_ms);

        // determine if to fail connection and close it immediately
        bool fail_conn = code == close_code::not_set || //
                         code == close_code::protocol_error ||
                         code == close_code::unacceptable_data_type ||
                         code == close_code::invalid_frame_payload_data ||
                         code == close_code::policy_violation ||
                         code == close_code::message_too_big ||
                         code == close_code::missing_extension ||
                         code == close_code::unexpected_condition;

        if (!fail_conn)
        {
            // send close frame
            auto res = this->send_close_frame(code, timeout);
            if (!res.has_value())
            {
#if WS_CLIENT_LOG_SEND_FRAME > 0
                logger_->template log<LogLevel::E, LogTopic::SendFrame>(std::format(
                    "Failed to send close frame with close code {}: {}",
                    to_string(code),
                    res.error()
                ));
#endif
                // indicate that the connection should be failed due to error
                fail_conn = true;
                code = close_code::not_set;
            }
        }

        if (fail_conn)
        {
            // client in error state, close connection immediately
            logger_->template log<LogLevel::E, LogTopic::TCP>(
                std::format("Failing connection with close code: {}", to_string(code))
            );
        }

        // mark as closed
        this->closed_ = true;

        // Shutdown socket communication (ignore errors, close socket anyway).
        // Often times, the server will close the connection after receiving the close frame,
        // which will result in an error when trying to shutdown the socket.
        this->socket_.underlying().shutdown(fail_conn, timeout);

        // close underlying socket connection
        {
            auto res = this->socket_.underlying().close(fail_conn);
            if (!res.has_value())
            {
#if WS_CLIENT_LOG_TCP > 0
                logger_->template log<LogLevel::W, LogTopic::TCP>(
                    std::format("Socket close failed: {}", res.error())
                );
#endif
                return std::unexpected(res.error());
            }
        }

        return expected<void, WSError>{};
    }

private:
    [[nodiscard]] expected<Frame, WSError> read_frame(Timeout<>& timeout)
    {
        Frame frame;

        // read frame header (2 bytes)
        byte tmp1[2];
        WS_TRYV(this->socket_.read_exact(span<byte>(tmp1, 2), timeout));

        frame.header.b0 = tmp1[0];
        frame.header.b1 = tmp1[1];

        if (!frame.header.is_final() && frame.header.op_code() == opcode::close) [[unlikely]]
        {
            return WS_ERROR(
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
            WS_TRYV(this->socket_.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp2), sizeof(uint16_t)), timeout
            ));
            payload_size = network_to_host(tmp2);
        }
        else
        {
            // 64 bit payload size
            uint64_t tmp3;
            WS_TRYV(this->socket_.read_exact(
                span<byte>(reinterpret_cast<byte*>(&tmp3), sizeof(uint64_t)), timeout
            ));
            payload_size = network_to_host(tmp3);
        }

        frame.payload_size = payload_size;

        // verify not masked
        if (frame.header.is_masked()) [[unlikely]]
        {
            return WS_ERROR(
                protocol_error, "Received masked frame from server.", close_code::protocol_error
            );
        }

#if WS_CLIENT_LOG_RECV_FRAME > 0
        if (logger_->template is_enabled<LogLevel::D, LogTopic::RecvFrame>())
        {
            logger_->template log<LogLevel::D, LogTopic::RecvFrame>(std::format(
                "Received {} frame rsv={:d} {:d} {:d} control={:d} final={:d} masked={:d} "
                "payload_size={}",
                to_string(frame.header.op_code()),
                frame.header.rsv1_bit(),
                frame.header.rsv2_bit(),
                frame.header.rsv3_bit(),
                frame.header.is_control(),
                frame.header.is_final(),
                frame.header.is_masked(),
                frame.payload_size
            ));
        }
#endif

        return frame;
    }

    [[nodiscard]] expected<void, WSError> write_frame(
        Frame& frame, span<byte> payload, Timeout<>& timeout
    ) noexcept
    {
#if WS_CLIENT_LOG_SEND_FRAME > 0
        if (logger_->template is_enabled<LogLevel::D, LogTopic::SendFrame>())
        {
            logger_->template log<LogLevel::D, LogTopic::SendFrame>(std::format(
                "Writing {} frame rsv={:d} {:d} {:d} control={:d} final={:d} masked={:d} "
                "payload_size={}",
                to_string(frame.header.op_code()),
                frame.header.rsv1_bit(),
                frame.header.rsv2_bit(),
                frame.header.rsv3_bit(),
                frame.header.is_control(),
                frame.header.is_final(),
                frame.header.is_masked(),
                frame.payload_size
            ));
        }
#endif

        size_t offset = 0;
        write_buffer_[0] = frame.header.b0;
        write_buffer_[1] = frame.header.b1;
        offset += 2;

        if (frame.payload_size > 125 && frame.payload_size <= UINT16_MAX) [[likely]]
        {
            // 16 bit payload length
            uint16_t nlen = host_to_network(static_cast<uint16_t>(frame.payload_size));
            std::memcpy(&write_buffer_[offset], &nlen, sizeof(uint16_t));
            offset += sizeof(uint16_t);
        }
        else if (frame.payload_size > UINT16_MAX) [[unlikely]]
        {
            // full 64 bit payload length
            uint64_t nlen = host_to_network(static_cast<uint64_t>(frame.payload_size));
            std::memcpy(&write_buffer_[offset], &nlen, sizeof(uint64_t));
            offset += sizeof(uint64_t);
        }

        if (!frame.header.is_masked())
        {
            return WS_ERROR(
                protocol_error, "Frame sent by client MUST be masked.", close_code::protocol_error
            );
        }

        // write 4 byte masking key
        std::memcpy(&write_buffer_[offset], &frame.mask_key.key, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // mask payload in-place
        frame.mask_key.mask(payload);

        // write frame header
        WS_TRYV(this->socket_.write(write_buffer_.subspan(0, offset), timeout));

        // write frame payload
        if (frame.payload_size > 0)
        {
            WS_TRYV(this->socket_.write(payload, timeout));
            offset += frame.payload_size;
        }

        return expected<void, WSError>{};
    }

    [[nodiscard]] expected<void, WSError> send_close_frame(
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
            std::memcpy(this->write_buffer_.data() + 125, &status_code_n, sizeof(uint16_t));
            payload = this->write_buffer_.subspan(125, sizeof(uint16_t));

#if WS_CLIENT_LOG_SEND_FRAME > 0
            logger_->template log<LogLevel::I, LogTopic::SendFrame>(std::format(
                "Writing close frame with status {} {}", static_cast<int>(code), to_string(code)
            ));
#endif
        }
        else
        {
#if WS_CLIENT_LOG_SEND_FRAME > 0
            // close frame without status code
            logger_->template log<LogLevel::I, LogTopic::SendFrame>("Writing close frame");
#endif
        }

        frame.set_payload_size(payload.size());

        WS_TRY(ret, this->write_frame(frame, payload, timeout));

#if WS_CLIENT_LOG_SEND_FRAME > 0
        logger_->template log<LogLevel::D, LogTopic::SendFrame>("Close frame sent");
#endif

        return expected<void, WSError>{};
    }

    [[nodiscard]] variant<PingFrame, PongFrame, CloseFrame, WSError> handle_control_frame(
        Frame& frame, Timeout<>& timeout
    ) noexcept
    {
        if (!frame.header.is_final())
        {
            return WSError(
                WSErrorCode::protocol_error,
                "Received fragmented control frame.",
                close_code::protocol_error
            );
        }

        if (frame.header.has_rsv_bits())
        {
            return WSError(
                WSErrorCode::protocol_error,
                "Invalid RSV bits found in control frame.",
                close_code::protocol_error
            );
        }

        if (frame.payload_size > 125)
        {
            return WSError(
                WSErrorCode::protocol_error,
                std::format(
                    "Control frame payload size larger than 125 bytes, got {}", frame.payload_size
                ),
                close_code::protocol_error
            );
        }

        switch (frame.header.op_code())
        {
            case opcode::close:
            {
#if WS_CLIENT_LOG_RECV_FRAME > 0
                if (!this->closed_)
                {
                    // close frame sent by server
                    logger_->template log<LogLevel::W, LogTopic::RecvFrame>(
                        "Unsolicited close frame received"
                    );
                }
#endif

                CloseFrame close_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    if (frame.payload_size == 1)
                    {
                        return WSError(
                            WSErrorCode::protocol_error,
                            "Invalid close frame payload size of 1.",
                            close_code::protocol_error
                        );
                    }

                    WS_TRYV_RAW(this->socket_.read_exact(close_frame.payload_bytes(), timeout));

                    // check close code if provided
                    if (close_frame.has_close_code())
                    {
                        auto code = close_frame.get_close_code();
                        if (!is_valid_close_code(code))
                        {
                            return WSError(
                                WSErrorCode::protocol_error,
                                std::format("Invalid close code {}", static_cast<uint16_t>(code)),
                                close_code::protocol_error
                            );
                        }
                    }

#if WS_CLIENT_VALIDATE_UTF8 == 1
                    // check close reason string is valid UTF-8 string
                    if (!close_frame.is_reason_valid_utf8())
                    {
                        return WSError(
                            WSErrorCode::protocol_error,
                            "Invalid UTF-8 in websocket close reason string.",
                            close_code::invalid_frame_payload_data
                        );
                    }
#endif
                }

                return close_frame;
            }

            case opcode::ping:
            {
                PingFrame ping_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_TRYV_RAW(this->socket_.read_exact(ping_frame.payload_bytes(), timeout));
                }

                return ping_frame;
            }

            case opcode::pong:
            {
                PongFrame pong_frame(frame.payload_size);

                // read control frame payload (max. 125 bytes)
                if (frame.payload_size > 0)
                {
                    WS_TRYV_RAW(this->socket_.read_exact(pong_frame.payload_bytes(), timeout));
                }

                return pong_frame;
            }

            default:
            {
                return WSError(
                    WSErrorCode::protocol_error,
                    std::format(
                        "Unexpected opcode for websocket control frame received: {}",
                        to_string(frame.header.op_code())
                    ),
                    close_code::protocol_error
                );
            }
        }
    }
};
} // namespace ws_client