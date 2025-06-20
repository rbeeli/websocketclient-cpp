#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <chrono>

#include "ws_client/errors.hpp"
#include "ws_client/utils/Timeout.hpp"

namespace ws_client
{
using byte = std::byte;

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
    [[nodiscard]] virtual std::expected<size_t, WSError> read_some(
        std::span<byte> buffer, Timeout<>& timeout
    ) noexcept = 0;

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] virtual std::expected<size_t, WSError> write_some(
        const std::span<const byte> data, Timeout<>& timeout
    ) noexcept = 0;

    /**
     * Shuts down the SSL layer.
     * This function should be called before closing the socket
     * for a clean shutdown of the SSL layer.
     * The return value in case of error may be ignored by the caller.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    virtual std::expected<void, WSError> shutdown(bool fail_connection, Timeout<>& timeout) noexcept = 0;

    /**
     * Close underlying socket.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    virtual std::expected<void, WSError> close(bool fail_connection) noexcept = 0;
};

} // namespace ws_client