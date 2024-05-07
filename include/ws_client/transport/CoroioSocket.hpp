#pragma once

#include <expected>
#include <cstddef>
#include <span>

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/ISocketAsync.hpp"

#include "coroio/ssl.hpp"
#include "coroio/corochain.hpp"

namespace ws_client
{
using std::span;
using std::byte;
using NNet::TValueTask;

template <typename TLogger, typename SocketType>
class CoroioSocket final : public ISocketAsync<TValueTask>
{
    TLogger* logger;
    SocketType socket;

public:
    explicit CoroioSocket(TLogger* logger, SocketType&& socket) noexcept
        : ISocketAsync<TValueTask>(), logger(logger), socket(std::move(socket))
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
        return this->socket;
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline TValueTask<expected<size_t, WSError>> read_some( //
        span<byte> buffer
    ) noexcept
    {
        try
        {
            int n = co_await this->socket.ReadSome(buffer.data(), buffer.size());
            if (n == 0)
                co_return WS_ERROR(TRANSPORT_ERROR, "Connection closed by peer", NOT_SET);
            else if (n == -1)
                co_return WS_ERROR(TRANSPORT_ERROR, "Read error", NOT_SET);
            co_return static_cast<size_t>(n);
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(TRANSPORT_ERROR, e.what(), NOT_SET);
        }
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] inline TValueTask<expected<size_t, WSError>> write_some( //
        span<byte> buffer
    ) noexcept
    {
        try
        {
            int n = co_await this->socket.WriteSome(buffer.data(), buffer.size());
            if (n == 0)
                co_return WS_ERROR(TRANSPORT_ERROR, "Connection closed by peer", NOT_SET);
            else if (n == -1)
                co_return WS_ERROR(TRANSPORT_ERROR, "Read error", NOT_SET);
            co_return static_cast<size_t>(n);
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(TRANSPORT_ERROR, e.what(), NOT_SET);
        }
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket
     * for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline TValueTask<expected<void, WSError>> shutdown() noexcept
    {
        // TODO: Not implemented in coroio
        co_return expected<void, WSError>{};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     */
    [[nodiscard]] inline TValueTask<expected<void, WSError>> close() noexcept
    {
        try
        {
            co_await this->socket.Close();
        }
        catch (const std::exception& e)
        {
            co_return WS_ERROR(TRANSPORT_ERROR, e.what(), NOT_SET);
        }
        co_return expected<void, WSError>{};
    }
};
} // namespace ws_client
