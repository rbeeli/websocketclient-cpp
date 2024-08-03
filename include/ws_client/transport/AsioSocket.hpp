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

namespace ws_client
{
using std::span;
using std::byte;
using asio::awaitable;
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
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * 
     * @return The number of bytes read, or an error.
     */
    [[nodiscard]] inline awaitable<expected<size_t, WSError>> read_some(
        span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        asio::error_code ec;
        auto buf = asio::buffer(buffer.data(), buffer.size());

        // set a timeout for the read operation
        read_timer_.expires_after(timeout.remaining());

        auto result = co_await (
            socket_.async_read_some(buf, asio::redirect_error(asio::use_awaitable, ec)) ||
            read_timer_.async_wait(asio::use_awaitable)
        );

        // check if timed out
        if (result.index() == 1)
        {
            // timer completed, indicating a timeout
            co_return WS_ERROR(timeout_error, "Read timed out", close_code::not_set);
        }

        if (ec)
            co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

        // return the number of bytes read
        co_return std::get<0>(result);
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * 
     * @return The number of bytes written, or an error.
     */
    [[nodiscard]] inline awaitable<expected<size_t, WSError>> write_some(
        const span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        asio::error_code ec;
        auto buf = asio::buffer(buffer.data(), buffer.size());

        // set a timeout for the write operation
        write_timer_.expires_after(timeout.remaining());

        auto result = co_await (
            asio::async_write(socket_, buf, asio::redirect_error(asio::use_awaitable, ec)) ||
            write_timer_.async_wait(asio::use_awaitable)
        );

        // check if timed out
        if (result.index() == 1)
        {
            // timer completed, indicating a timeout
            co_return WS_ERROR(timeout_error, "Write timed out", close_code::not_set);
        }

        if (ec)
            co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

        // return the number of bytes written
        co_return std::get<0>(result);
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline awaitable<expected<void, WSError>> shutdown(Timeout<>& timeout) noexcept
    {
        logger_->template log<LogLevel::D>("Cancelling socket operations");

        // cancel all outstanding asynchronous operations
        socket_.lowest_layer().cancel();

        if constexpr (std::is_same<SocketType, asio::ssl::stream<asio::ip::tcp::socket>>::value)
        {
            logger_->template log<LogLevel::D>("SSL before async_shutdown");

            // asynchronously shut down the SSL connection, but don't wait
            asio::error_code ec;
            asio::steady_timer timer{socket_.get_executor()};
            timer.expires_after(timeout.remaining());
            auto res = co_await (
                socket_.async_shutdown(asio::redirect_error(asio::use_awaitable, ec)) ||
                timer.async_wait(asio::use_awaitable)
            );
            timer.cancel();

            // check if timed out
            if (res.index() == 1)
            {
                logger_->template log<LogLevel::W>("SSL async_shutdown timed out");
            }

            if (ec && ec != asio::error::eof)
                co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);
        }

        logger_->template log<LogLevel::D>("TCP before shutdown");

        // shut down the (underlying) TCP connection
        asio::error_code ec;
        socket_.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::eof)
            co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

        logger_->template log<LogLevel::D>("TCP after shutdown");

        co_return expected<void, WSError>{};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline awaitable<expected<void, WSError>> close() noexcept
    {
        asio::error_code ec;

        logger_->template log<LogLevel::D>("TCP before close");

        // close the underlying socket
        socket_.lowest_layer().close(ec);
        if (ec)
            co_return WS_ERROR(transport_error, ec.message(), close_code::not_set);

        logger_->template log<LogLevel::I>("TCP connection closed");

        co_return expected<void, WSError>{};
    }
};
} // namespace ws_client
