#pragma once

#include <expected>
#include <cstddef>
#include <span>

#include "coroio/ssl.hpp"
#include "coroio/corochain.hpp"

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/transport/ISocketAsync.hpp"

namespace ws_client
{
using byte = std::byte;
using NNet::TValueTask;

template <typename TLogger, typename SocketType>
class CoroioSocket final : public ISocketAsync<TValueTask>
{
private:
    TLogger* logger_;
    SocketType socket_;

public:
    explicit CoroioSocket(TLogger* logger, SocketType&& socket) noexcept
        : ISocketAsync<TValueTask>(), logger_(logger), socket_(std::move(socket))
    {
    }

    // delete copy
    CoroioSocket(const CoroioSocket&) = delete;
    CoroioSocket& operator=(const CoroioSocket&) = delete;

    // enable move
    CoroioSocket(CoroioSocket&&) noexcept = default;
    CoroioSocket& operator=(CoroioSocket&&) noexcept = default;

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
    [[nodiscard]] inline TValueTask<std::expected<size_t, WSError>> read_some(
        span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        try
        {
            int n = co_await socket_.ReadSome(buffer.data(), buffer.size());
            if (n == 0)
                co_return WS_ERROR(connection_closed, "Connection closed by peer", close_code::not_set);
            else if (n == -1)
                co_return WS_ERROR(transport_error, "Read error", close_code::not_set);
            co_return static_cast<size_t>(n);
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(transport_error, e.what(), close_code::not_set);
        }
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * 
     * @return The number of bytes written, or an error.
     */
    [[nodiscard]] inline TValueTask<std::expected<size_t, WSError>> write_some(
        const std::span<const byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        // TODO: Implement timeout
        try
        {
            int n = co_await socket_.WriteSome(buffer.data(), buffer.size());
            if (n == 0)
                co_return WS_ERROR(connection_closed, "Connection closed by peer", close_code::not_set);
            else if (n == -1)
                co_return WS_ERROR(transport_error, "Read error", close_code::not_set);
            co_return static_cast<size_t>(n);
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(transport_error, e.what(), close_code::not_set);
        }
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket
     * for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline TValueTask<std::expected<void, WSError>> shutdown(bool fail_connection, Timeout<>& timeout) noexcept
    {
        // TODO: Not implemented in coroio
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
    [[nodiscard]] inline TValueTask<std::expected<void, WSError>> close(bool fail_connection) noexcept
    {
        try
        {
            co_await socket_.Close();
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(transport_error, e.what(), close_code::not_set);
        }
        co_return std::expected<void, WSError>{};
    }
};
} // namespace ws_client
