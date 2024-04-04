#pragma once

#include <expected>
#include <cstddef>
#include <span>

#include "ws_client/errors.hpp"

namespace ws_client
{
using std::byte;
using std::span;

/**
 * Base class for blocking socket implementations (raw TCP, SSL, etc.).
 */
class ISocket
{
public:
    ISocket() noexcept = default;

    virtual ~ISocket() noexcept = default;

    // disable copy
    ISocket(const ISocket&) = delete;
    ISocket& operator=(const ISocket&) = delete;

    // enable move
    ISocket(ISocket&&) noexcept = default;
    ISocket& operator=(ISocket&&) noexcept = default;

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] virtual expected<size_t, WSError> read_some(span<byte> buffer) noexcept = 0;

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] virtual expected<size_t, WSError> write_some(const span<byte> data) noexcept = 0;

    /**
     * Shuts down the SSL layer.
     * This function should be called before closing the socket
     * for a clean shutdown of the SSL layer.
     * The return value in case of error may be ignored by the caller.
     */
    virtual expected<void, WSError> shutdown() noexcept = 0;
    
    /**
     * Close underlying socket.
     */
    virtual expected<void, WSError> close() noexcept = 0;
};

} // namespace ws_client