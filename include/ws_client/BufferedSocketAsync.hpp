#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <algorithm>
#include <chrono>
#include <cassert>

#include "ws_client/errors_async.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/string.hpp"
#include "ws_client/utils/CircularBuffer.hpp"
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/transport/HasSocketOperationsAsync.hpp"
#include "ws_client/Buffer.hpp"

namespace ws_client
{
using std::string;
using std::byte;
using std::span;
using std::optional;

template <typename TSocket, template <typename...> typename TTask>
    requires HasSocketOperationsAsync<TSocket, TTask>
class BufferedSocketAsync final
{
    static constexpr int read_buffer_size = 4096;

private:
    TSocket socket_;
    CircularBuffer<byte> read_buffer_;

public:
    explicit BufferedSocketAsync(TSocket&& socket) noexcept
        : socket_(std::move(socket)), read_buffer_(read_buffer_size)
    {
    }

    // disable copy
    BufferedSocketAsync(const BufferedSocketAsync&) = delete;
    BufferedSocketAsync& operator=(const BufferedSocketAsync&) = delete;

    // enable move
    BufferedSocketAsync(BufferedSocketAsync&&) noexcept = default;
    BufferedSocketAsync& operator=(BufferedSocketAsync&&) noexcept = default;

    [[nodiscard]] inline TSocket& underlying() noexcept
    {
        return socket_;
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline TTask<expected<size_t, WSError>> read_some(
        span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        co_return co_await socket_.read_some(buffer, timeout);
    }

    /**
     * Reads len bytes from the socket and stores them in destination.
     * Reads exactly 'length' bytes, unless an error occurs, usually due to
     * connection closure by peer.
     */
    [[nodiscard]] TTask<expected<size_t, WSError>> read_exact(
        span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        size_t total_read = 0;
        size_t remaining = buffer.size();
        while (remaining > 0)
        {
            WS_CO_TRY(res, co_await this->fill_read_buffer(remaining, timeout));
            size_t read_bytes = *res;

            // copy from read buffer to destination buffer
            read_buffer_.pop(buffer.data() + total_read, read_bytes);

            total_read += read_bytes;
            remaining -= read_bytes;
        }

        co_return total_read;
    }

    /**
     * Reads from the socket into the passed buffer until the delimiter is found.
     * The delimiter is not included in the buffer.
     */
    template <HasBufferOperations TBuffer>
    [[nodiscard]] TTask<expected<void, WSError>> read_until(
        TBuffer& buffer, const span<byte> delimiter, Timeout<>& timeout
    ) noexcept
    {
        size_t search_offset = 0;
        while (true)
        {
            // read some data into circular buffer
            WS_CO_TRYV(co_await this->fill_read_buffer(read_buffer_.capacity(), timeout));

            // append circular buffer data to buffer
            WS_CO_TRY(cb_read_span_res, buffer.append(read_buffer_.size()));
            span<byte> cb_read_span = *cb_read_span_res;
            read_buffer_.pop(cb_read_span);

            // std::cout << string_from_bytes(cb_read_span) << std::endl;

            // try to find delimiter in buffer
            auto buffer_start = buffer.data().data();
            auto search_start = buffer_start + search_offset -
                                std::min(search_offset, delimiter.size() - 1);
            auto buffer_end = buffer_start + buffer.size();
            auto res = std::search(search_start, buffer_end, delimiter.begin(), delimiter.end());
            if (res != buffer_end)
            {
                // delimiter found.
                // move delimiter and after back into circular buffer
                read_buffer_.push(res, buffer_end - res);

                // remove data starting from delimiter from buffer
                WS_CO_TRYV(buffer.resize(res - buffer_start));

                co_return expected<void, WSError>{};
            }
            else
            {
                // delimiter not found.
                // move search offset to the end of buffer
                search_offset = buffer.size();
            }
        }
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] inline TTask<expected<size_t, WSError>> write_some(
        const span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        co_return co_await socket_.write_some(buffer.data(), buffer.size(), timeout);
    }

    /**
     * Writes all data in `buffer` to underlying socket, or returns an error.
     * Does not perform partial writes unless an error occurs.
     */
    [[nodiscard]] inline TTask<expected<void, WSError>> write(
        const span<byte> buffer, Timeout<>& timeout
    ) noexcept
    {
        size_t size = buffer.size();
        byte* p = buffer.data();
        while (size != 0)
        {
            WS_CO_TRY(ret_res, co_await socket_.write_some(span<byte>(p, size), timeout));
            auto ret = *ret_res;

            if (ret == 0) [[unlikely]]
                co_return WS_ERROR(transport_error, "Socket closed by peer", not_set);

            if (ret < 0) [[unlikely]]
                continue; // retry on interrupt signal or socket not ready for write

            p += ret;
            size -= ret;
        }
        co_return expected<void, WSError>{};
    }

private:
    [[nodiscard]] TTask<expected<size_t, WSError>> fill_read_buffer(
        const size_t desired_bytes, Timeout<>& timeout
    ) noexcept
    {
        assert(desired_bytes > 0 && "Desired bytes must be greater than 0");

        if (read_buffer_.size() >= desired_bytes)
            co_return desired_bytes; // already have enough bytes in buffer

        // directly read into circular buffer.
        // due to the cirular nature of the buffer,
        // available_as_contiguous_span might return a span that's shorter
        // than the available space in the buffer, because it can only return
        // a single continguous span (from head to end of buffer or from start to tail).
        span<byte> buf_span = read_buffer_.available_as_contiguous_span();
        WS_CO_TRY(res, co_await this->read_some(buf_span, timeout));

        // move head by the number of bytes read into buffer
        read_buffer_.move_head(res.value());

        size_t n_read = read_buffer_.size() < desired_bytes //
                            ? read_buffer_.size()
                            : desired_bytes;
        co_return n_read;
    }
};

} // namespace ws_client
