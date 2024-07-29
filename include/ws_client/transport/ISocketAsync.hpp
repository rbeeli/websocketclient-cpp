#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <chrono>

#include "ws_client/errors_async.hpp"

namespace ws_client
{
using std::byte;
using std::span;

/**
 * Base class for non-blocking asynchronous socket implementations (raw TCP, SSL, etc.).
 */
template <template <typename...> typename TTask>
class ISocketAsync
{
public:
    ISocketAsync() noexcept = default;

    virtual ~ISocketAsync() noexcept = default;

    // disable copy
    ISocketAsync(const ISocketAsync&) = delete;
    ISocketAsync& operator=(const ISocketAsync&) = delete;

    // enable move
    ISocketAsync(ISocketAsync&&) = default;
    ISocketAsync& operator=(ISocketAsync&&) = default;

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] virtual TTask<expected<size_t, WSError>> read_some(span<byte> buffer
    ) noexcept = 0;

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] virtual TTask<expected<size_t, WSError>> write_some(
        const span<byte> data, std::chrono::milliseconds timeout
    ) noexcept = 0;

    /**
     * Shuts down the SSL layer.
     * This function should be called before closing the socket
     * for a clean shutdown of the SSL layer.
     * The return value in case of error may be ignored by the caller.
     */
    virtual TTask<expected<void, WSError>> shutdown(std::chrono::milliseconds timeout) noexcept = 0;

    /**
     * Close underlying socket.
     */
    virtual TTask<expected<void, WSError>> close() noexcept = 0;
};

} // namespace ws_client