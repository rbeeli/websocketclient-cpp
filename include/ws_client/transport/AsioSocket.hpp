#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <chrono>

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/ISocketAsync.hpp"

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>

namespace ws_client
{
using std::span;
using std::byte;
using asio::awaitable;
using namespace asio::experimental::awaitable_operators;

template <typename TLogger, typename SocketType>
class AsioSocket final : public ISocketAsync<awaitable>
{
    TLogger* logger;
    SocketType socket;
    asio::steady_timer write_timer;

public:
    explicit AsioSocket(TLogger* logger, SocketType&& socket) noexcept
        : ISocketAsync<awaitable>(),
          logger(logger),
          socket(std::move(socket)),
          write_timer(this->socket.get_executor())
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
        return this->socket;
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline awaitable<expected<size_t, WSError>> read_some(span<byte> buffer) noexcept
    {
        asio::error_code ec;
        auto buf = asio::buffer(buffer.data(), buffer.size());
        size_t n = co_await this->socket.async_read_some(
            buf, asio::redirect_error(asio::use_awaitable, ec)
        );
        if (ec)
            co_return WS_ERROR(TRANSPORT_ERROR, ec.message(), NOT_SET);
        co_return n;
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] inline awaitable<expected<size_t, WSError>> write_some(
        const span<byte> buffer, std::chrono::milliseconds timeout
    ) noexcept
    {
        // set a timeout for the write operation
        write_timer.expires_after(timeout);

        asio::error_code ec;
        auto buf = asio::buffer(buffer.data(), buffer.size());

        auto result = co_await (
            asio::async_write(this->socket, buf, asio::redirect_error(asio::use_awaitable, ec)) ||
            write_timer.async_wait(asio::use_awaitable)
        );

        // check which operation completed
        if (result.index() == 1)
        {
            // cancel all outstanding asynchronous operations
            this->socket.lowest_layer().cancel();

            // timer completed, indicating a timeout
            co_return WS_ERROR(TRANSPORT_ERROR, "Write timed out", NOT_SET);
        }

        if (ec)
            co_return WS_ERROR(TRANSPORT_ERROR, ec.message(), NOT_SET);

        // return the number of bytes written
        co_return std::get<0>(result);
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline awaitable<expected<void, WSError>> shutdown(
        std::chrono::milliseconds timeout
    ) noexcept
    {
        logger->template log<LogLevel::D>("Cancelling socket operations");

        // cancel all outstanding asynchronous operations
        this->socket.lowest_layer().cancel();

        if constexpr (std::is_same<SocketType, asio::ssl::stream<asio::ip::tcp::socket>>::value)
        {
            logger->template log<LogLevel::D>("SSL before async_shutdown");

            // asynchronously shut down the SSL connection, but don't wait
            asio::error_code ec;
            asio::steady_timer timer{this->socket.get_executor()};
            timer.expires_after(timeout);
            auto res = co_await (
                this->socket.async_shutdown(asio::redirect_error(asio::use_awaitable, ec)) ||
                timer.async_wait(asio::use_awaitable)
            );
            timer.cancel();

            if (res.index() == 1)
            {
                logger->template log<LogLevel::W>("SSL async_shutdown timed out");
            }

            if (ec && ec != asio::error::eof)
                co_return WS_ERROR(TRANSPORT_ERROR, ec.message(), NOT_SET);
        }

        logger->template log<LogLevel::D>("TCP before shutdown");

        // asynchronously shut down the (underlying) TCP connection
        asio::error_code ec;
        this->socket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::eof)
            co_return WS_ERROR(TRANSPORT_ERROR, ec.message(), NOT_SET);

        logger->template log<LogLevel::D>("TCP after shutdown");

        co_return expected<void, WSError>{};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline awaitable<expected<void, WSError>> close() noexcept
    {
        asio::error_code ec;

        logger->template log<LogLevel::D>("TCP before close");

        // close the underlying socket
        this->socket.lowest_layer().close(ec);
        if (ec)
            co_return WS_ERROR(TRANSPORT_ERROR, ec.message(), NOT_SET);

        logger->template log<LogLevel::I>("TCP connection closed");

        co_return expected<void, WSError>{};
    }
};
} // namespace ws_client
