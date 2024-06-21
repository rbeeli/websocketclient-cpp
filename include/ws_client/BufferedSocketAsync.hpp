#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <algorithm>
#include <chrono>
#include <cassert>

#include "ws_client/errors_async.hpp"
#include "ws_client/utils/string.hpp"
#include "ws_client/utils/CircularBuffer.hpp"
#include "ws_client/log.hpp"
#include "ws_client/Buffer.hpp"
#include "ws_client/concepts_async.hpp"

namespace ws_client
{
using std::string;
using std::byte;
using std::span;
using std::optional;

template <typename TSocket, template <typename> typename TTask>
    requires HasAsyncSocketOperations<TSocket, TTask>
class BufferedSocketAsync final
{
    static constexpr int read_buffer_size = 4096;

private:
    TSocket socket;
    CircularBuffer<byte> read_buffer;


public:
    explicit BufferedSocketAsync(TSocket&& socket) noexcept
        : socket(std::move(socket)), read_buffer(read_buffer_size)
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
        return this->socket;
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline TTask<expected<size_t, WSError>> read_some(span<byte> buffer) noexcept
    {
        co_return co_await this->socket.read_some(buffer);
    }

    /**
     * Reads len bytes from the socket and stores them in destination.
     * Reads exactly 'length' bytes, unless an error occurs, usually due to
     * connection closure by peer.
     */
    [[nodiscard]] TTask<expected<size_t, WSError>> read_exact(span<byte> buffer) noexcept
    {
        size_t total_read = 0;
        size_t remaining = buffer.size();
        while (remaining > 0)
        {
            WS_CO_TRY(res, co_await this->fill_read_buffer(remaining));
            size_t read_bytes = *res;

            // copy from read buffer to destination buffer
            this->read_buffer.pop(buffer.data() + total_read, read_bytes);

            total_read += read_bytes;
            remaining -= read_bytes;
        }

        co_return total_read;
    }

    /**
     * Reads from the socket into the passed buffer until the delimiter is found.
     * The delimiter is not included in the buffer.
     * 
     * Note: The timeout is only for the read-loop, not for individual reads / read-calls.
     * If a read call never returns, the timeout will not be triggered.
     */
    template <HasBufferOperations TBuffer>
    [[nodiscard]] TTask<expected<void, WSError>> read_until(
        TBuffer& buffer, const span<byte> delimiter, optional<std::chrono::milliseconds> timeout
    ) noexcept
    {
        auto start = std::chrono::system_clock::now();
        size_t search_offset = 0;
        while (true)
        {
            if (timeout.has_value())
            {
                auto elapsed = std::chrono::system_clock::now() - start;
                if (elapsed > timeout.value())
                    co_return WS_ERROR(TIMEOUT, "read_until timed out.", NOT_SET);
            }

            // read some data into circular buffer
            WS_CO_TRYV(co_await this->fill_read_buffer(this->read_buffer.capacity()));

            // append circular buffer data to buffer
            WS_CO_TRY(cb_read_span_res, buffer.append(this->read_buffer.size()));
            span<byte> cb_read_span = *cb_read_span_res;
            this->read_buffer.pop(cb_read_span);

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
                this->read_buffer.push(res, buffer_end - res);

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
        const span<byte> buffer, std::chrono::milliseconds timeout
    ) noexcept
    {
        co_return co_await this->socket.write_some(buffer.data(), buffer.size(), timeout);
    }

    /**
     * Writes all data in `buffer` to underlying socket, or returns an error.
     * Does not perform partial writes unless an error occurs.
     */
    [[nodiscard]] inline TTask<expected<void, WSError>> write(
        const span<byte> buffer, std::chrono::milliseconds timeout
    ) noexcept
    {
        size_t size = buffer.size();
        byte* p = buffer.data();
        while (size != 0)
        {
            WS_CO_TRY(ret_res, co_await this->socket.write_some(span<byte>(p, size), timeout));
            auto ret = *ret_res;

            if (ret == 0) [[unlikely]]
                co_return WS_ERROR(TRANSPORT_ERROR, "Socket closed by peer", NOT_SET);

            if (ret < 0) [[unlikely]]
                continue; // retry on interrupt signal or socket not ready for write

            p += ret;
            size -= ret;
        }
        co_return expected<void, WSError>{};
    }

private:
    [[nodiscard]] TTask<expected<size_t, WSError>> fill_read_buffer(const size_t desired_bytes
    ) noexcept
    {
        assert(desired_bytes > 0 && "Desired bytes must be greater than 0");

        if (read_buffer.size() >= desired_bytes)
            co_return desired_bytes; // already have enough bytes in buffer

        // directly read into circular buffer.
        // due to the cirular nature of the buffer,
        // available_as_contiguous_span might return a span that's shorter
        // than the available space in the buffer, because it can only return
        // a single continguous span (from head to end of buffer or from start to tail).
        span<byte> buf_span = this->read_buffer.available_as_contiguous_span();
        WS_CO_TRY(res, co_await this->read_some(buf_span));

        // move head by the number of bytes read into buffer
        this->read_buffer.move_head(res.value());

        size_t n_read = this->read_buffer.size() < desired_bytes ? this->read_buffer.size()
                                                                 : desired_bytes;
        co_return n_read;
    }
};

} // namespace ws_client
