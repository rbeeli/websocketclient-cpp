#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <chrono>

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/transport/ISocketAsync.hpp"
#include "ws_client/transport/ssl_utils.hpp"

namespace ws_client
{
using byte = std::byte;
using namespace asio::experimental::awaitable_operators;

template <typename TLogger, typename SocketType>
class AsioSocket final : public ISocketAsync<asio::awaitable>
{
private:
    TLogger* logger_;
    SocketType socket_;
    asio::steady_timer read_timer_;
    asio::steady_timer write_timer_;

public:
    explicit AsioSocket(TLogger* logger, SocketType&& socket) noexcept
        : ISocketAsync<asio::awaitable>(),
          logger_(logger),
          socket_(std::move(socket)),
          read_timer_(socket_.get_executor()),
          write_timer_(socket_.get_executor())
    {
    }

    // disable copy
    AsioSocket(const AsioSocket&) = delete;
    AsioSocket& operator=(const AsioSocket&) = delete;

    // enable move
    AsioSocket(AsioSocket&&) = default;
    AsioSocket& operator=(AsioSocket&&) = default;

    inline SocketType& underlying() noexcept
    {
        return socket_;
    }

    /**
     * Checks if there is data available to be read from the socket without consuming it.
     * For SSL sockets, this checks for actual application data, not just SSL protocol bytes.
     * 
     * Note that the method returns immediately, thus using the return value as loop
     * condition results in CPU intensive busy-spinning if there is no sleep or yielding
     * done by the caller.
     * 
     * @return true if there is data available to read, false if not,
     *         or WSError in case of any unexpected errors.
     */
    [[nodiscard]] inline std::expected<bool, WSError> can_read() noexcept
    {
        if constexpr (std::is_same_v<SocketType, asio::ssl::stream<asio::ip::tcp::socket>>)
        {
            auto* ssl = socket_.native_handle();
            if (!ssl)
                return WS_ERROR(transport_error, "Invalid SSL handle", close_code::not_set);

            char buf[1];

            // Keep retrying on EINTR
            do
            {
                // try to read one byte without consuming it
                ERR_clear_error();
                int ret = SSL_peek(ssl, buf, 1);
                int ssl_err = SSL_get_error(ssl, ret);

                if (ssl_err == SSL_ERROR_NONE) [[likely]]
                {
                    // data is available to read
                    return true;
                }
                else if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                {
                    return false;
                }
                else if (ssl_err == SSL_ERROR_SYSCALL)
                {
                    const int errno_ = errno;

                    if (errno_ == EINTR)
                        continue; // interrupted, retry immediately

                    if (errno_ == 0)
                        return WS_ERROR(
                            connection_closed,
                            "TLS peer closed connection abruptly",
                            close_code::not_set
                        );

                    return syscall_error(ret, errno_, "SSL syscall error in wait_readable");
                }
                else if (ssl_err == SSL_ERROR_ZERO_RETURN)
                {
                    ERR_clear_error(); // manually drain SSL error queue
                    return WS_ERROR(
                        connection_closed,
                        "SSL connection closed in wait_readable (SSL_ERROR_ZERO_RETURN)",
                        close_code::not_set
                    );
                }
                else
                {
                    return ssl_error(ret, ssl_err, "Unexpected SSL error in wait_readable");
                }
            } while (true);
        }
        else
        {
            asio::error_code ec;
            auto available = socket_.available(ec);
            if (ec)
                return WS_ERROR(transport_error, ec.message(), close_code::not_set);
            return available > 0;
        }
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * 
     * @return The number of bytes read, or an error.
     */
    [[nodiscard]] inline asio::awaitable<std::expected<size_t, WSError>> read_some(
        std::span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        auto buf = asio::buffer(buffer.data(), buffer.size());

        // set a timeout for the read operation
        read_timer_.expires_after(timeout.remaining());

        // both operations must use redirect_error, otherwise bus error on ARM64 (not x86 though)!
        asio::error_code ec1;
        asio::error_code ec2;
        auto result = co_await (
            socket_.async_read_some(buf, asio::redirect_error(asio::use_awaitable, ec1)) ||
            read_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec2))
        );

        // check if timed out
        if (result.index() == 1)
        {
            // timer completed, indicating a timeout
            co_return WS_ERROR(timeout_error, "Read timed out", close_code::not_set);
        }

        // cancel timer
        read_timer_.cancel();

        if (ec1)
            co_return WS_ERROR(transport_error, ec1.message(), close_code::not_set);

        // return the number of bytes read
        co_return std::get<0>(result);
    }

    /**
     * Writes all of `buffer` to underlying socket.
     * 
     * In case of timeout or error, the connection should be terminated
     * as the number of bytes transmitted is unknown.
     * 
     * @return The number of bytes written, or an error.
     */
    [[nodiscard]] inline asio::awaitable<std::expected<size_t, WSError>> write_some(
        const std::span<const byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        auto buf = asio::buffer(buffer.data(), buffer.size());

        // set a timeout for the write operation
        write_timer_.expires_after(timeout.remaining());

        // both operations must use redirect_error, otherwise bus error on ARM64 (not x86 though)!
        asio::error_code ec1;
        asio::error_code ec2;
        auto result = co_await (
            asio::async_write(socket_, buf, asio::redirect_error(asio::use_awaitable, ec1)) ||
            write_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec2))
        );

        // check if timed out
        if (result.index() == 1)
        {
            // timer completed, indicating a timeout
            co_return WS_ERROR(timeout_error, "Write timed out", close_code::not_set);
        }

        // cancel timer
        write_timer_.cancel();

        if (ec1)
            co_return WS_ERROR(transport_error, ec1.message(), close_code::not_set);

        // return the number of bytes written
        co_return std::get<0>(result);
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    [[nodiscard]] inline asio::awaitable<std::expected<void, WSError>> shutdown(
        bool fail_connection, Timeout<>& timeout
    ) noexcept
    {
#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>("Cancelling socket operations");
#endif

        // cancel all outstanding asynchronous operations
        socket_.lowest_layer().cancel();

        if (!fail_connection)
        {
            if constexpr (std::is_same_v<SocketType, asio::ssl::stream<asio::ip::tcp::socket>>)
            {
                // shut down the SSL layer gracefully.
                // we must do this in ASIO even for failed connections, to ensure all operations are cancelled,
                // otherwise the socket will be closed immediately, but the operations will still be running
                // and may cause a crash.

#if WS_CLIENT_LOG_SSL > 0
                logger_->template log<LogLevel::D, LogTopic::SSL>("SSL before async_shutdown");
#endif

                // asynchronously shut down the SSL connection, but don't wait.
                // both operations must use redirect_error, otherwise bus error on ARM64 (not x86 though)!
                asio::error_code ec1;
                asio::error_code ec2;
                asio::steady_timer timer{socket_.get_executor()};
                timer.expires_after(timeout.remaining());
                ERR_clear_error();
                auto res = co_await (
                    socket_.async_shutdown(asio::redirect_error(asio::use_awaitable, ec1)) ||
                    timer.async_wait(asio::redirect_error(asio::use_awaitable, ec2))
                );

                // check if timed out (ignore error)
                if (res.index() == 1)
                {
#if WS_CLIENT_LOG_SSL > 0
                    logger_->template log<LogLevel::W, LogTopic::SSL>("SSL async_shutdown timed out"
                    );

#endif
                }

                // cancel timer
                timer.cancel();

                // shutdown failed
                if (ec1 && ec1 != asio::error::eof)
                    co_return WS_ERROR(transport_error, ec1.message(), close_code::not_set);
            }

#if WS_CLIENT_LOG_TCP > 0
            logger_->template log<LogLevel::D, LogTopic::TCP>("TCP before shutdown");
#endif

            // shut down the (underlying) TCP connection
            asio::error_code ec;
            socket_.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec && ec != asio::error::eof)
                co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

#if WS_CLIENT_LOG_TCP > 0
            logger_->template log<LogLevel::D, LogTopic::TCP>("TCP after shutdown");
#endif
        }

        co_return std::expected<void, WSError>{};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    [[nodiscard]] inline asio::awaitable<std::expected<void, WSError>> close(
        bool fail_connection
    ) noexcept
    {
        asio::error_code ec;

#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>("TCP before close");
#endif

        // close the underlying socket
        socket_.lowest_layer().close(ec);
        if (ec)
            co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::I, LogTopic::TCP>("TCP connection closed");
#endif

        co_return std::expected<void, WSError>{};
    }
};
} // namespace ws_client
