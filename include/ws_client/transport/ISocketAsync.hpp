#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <chrono>

#include "ws_client/errors_async.hpp"
#include "ws_client/utils/Timeout.hpp"

namespace ws_client
{
using byte = std::byte;

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
     * Checks if there is data available to be read from the socket without consuming it.
     * For SSL sockets, this checks for actual application data, not just SSL protocol bytes.
     * 
     * @return true if there is data available to read, false if not,
     *         or WSError in case of any unexpected errors.
     */
    [[nodiscard]] virtual inline std::expected<bool, WSError> can_read() noexcept = 0;

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] virtual TTask<std::expected<size_t, WSError>> read_some(
        std::span<byte> buffer, Timeout<>& timeout
    ) noexcept = 0;

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] virtual TTask<std::expected<size_t, WSError>> write_some(
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
    virtual TTask<std::expected<void, WSError>> shutdown(
        bool fail_connection, Timeout<>& timeout
    ) noexcept = 0;

    /**
     * Close underlying socket.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    virtual TTask<std::expected<void, WSError>> close(bool fail_connection) noexcept = 0;
};

} // namespace ws_client