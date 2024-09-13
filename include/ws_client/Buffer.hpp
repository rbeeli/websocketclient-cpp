#pragma once

#include <expected>
#include <cstddef>
#include <cstring>
#include <format>
#include <algorithm>
#include <span>
#include <concepts>
#include <cassert>

#include "ws_client/errors.hpp"
#include "ws_client/HasBufferOperations.hpp"

namespace ws_client
{
using std::byte;
using std::span;

/**
 * A simple buffer class for storing binary data, similar to `std::vector<byte>`.
 * The buffer can be resized and data can be appended to it.
 */
class Buffer
{
private:
    size_t max_size_;
    size_t capacity_;
    size_t used_;
    byte* buffer_ = nullptr;

    /**
     * Private constructor to create a buffer with a maximum size.
     * Use the factory method `create` to create a new buffer.
     */
    explicit Buffer(size_t max_size) noexcept //
        : max_size_(max_size), capacity_(0), used_(0)
    {
    }

public:
    /**
     * Factory method to create a new buffer with an initial size and maximum size.
     */
    [[nodiscard]] static expected<Buffer, WSError> create(
        size_t initial_size, size_t max_size
    ) noexcept
    {
        assert(initial_size <= max_size && "Initial size must be less than or equal to max size");
        Buffer buffer(max_size);
        WS_TRYV(buffer.reserve(initial_size));
        return buffer;
    }

    ~Buffer() noexcept
    {
        std::free(buffer_);
        buffer_ = nullptr;
    }

    // delete copy constructor and copy assignment operator
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    // move constructor and move assignment operator
    Buffer(Buffer&& other) noexcept
        : max_size_(other.max_size_),
          capacity_(other.capacity_),
          used_(other.used_),
          buffer_(other.buffer_)
    {
        other.buffer_ = nullptr;
        other.capacity_ = 0;
        other.used_ = 0;
    }
    Buffer& operator=(Buffer&& other) noexcept
    {
        if (this != &other)
        {
            std::free(buffer_);
            max_size_ = other.max_size_;
            capacity_ = other.capacity_;
            used_ = other.used_;
            buffer_ = other.buffer_;
            other.buffer_ = nullptr;
            other.capacity_ = 0;
            other.used_ = 0;
        }
        return *this;
    }

    /**
     * Get the number of bytes currently stored in the buffer.
     */
    [[nodiscard]] inline size_t size() const noexcept
    {
        return used_;
    }

    /**
     * Get the current number of allocated bytes.
     * This is the actual memory size allocated for the buffer.
     * The buffer size can be smaller than the allocated memory size.
     */
    [[nodiscard]] inline size_t allocated() const noexcept
    {
        return capacity_;
    }

    /**
     * Clears the buffer data.
     * Does not deallocate the buffer or shrink memory usage.
     * Use `reset` to resize the physical buffer and reduce memory usage.
     */
    inline void clear() noexcept
    {
        used_ = 0;
    }

    /**
     * Deallocate the buffer and reset its state.
     */
    inline void reset() noexcept
    {
        std::free(buffer_);
        buffer_ = nullptr;
        capacity_ = 0;
        used_ = 0;
    }

    /**
     * Check if buffer is empty, i.e. contains no data.
     */
    [[nodiscard]] inline bool empty() const noexcept
    {
        return used_ == 0;
    }

    /**
     * Check if buffer is full, meaning it has reached
     * the maximum allowed size `max_size`.
     */
    [[nodiscard]] inline bool full() const noexcept
    {
        return used_ == max_size_;
    }

    [[nodiscard]] inline byte& at(size_t pos) noexcept
    {
        assert(pos < used_ && "Buffer index out of bounds");
        return buffer_[pos];
    }

    [[nodiscard]] inline byte& operator[](size_t pos) noexcept
    {
        assert(pos < used_ && "Buffer index out of bounds");
        return buffer_[pos];
    }

    /**
     * Set the maximum allowed buffer size / capacity.
     */
    void set_max_size(size_t max_size) noexcept
    {
        max_size_ = max_size;
    }

    /**
     * Get the maximum allowed buffer size / capacity.
     */
    [[nodiscard]] size_t max_size() const noexcept
    {
        return max_size_;
    }

    /**
     * Reserve space for at least `size` bytes in the buffer.
     * Only performs allocation if the requested size is greater than the current capacity.
     */
    [[nodiscard]] inline expected<void, WSError> reserve(size_t size) noexcept
    {
        if (size > capacity_)
            WS_TRYV(internal_reserve(size));
        return {};
    }

    /**
     * Resize the buffer to `size` bytes.
     * The buffer data can then be accessed using the `data` method.
     * The allocated space is exactly `size` bytes after this operation.
     */
    [[nodiscard]] inline expected<void, WSError> resize(size_t size) noexcept
    {
        if (size != capacity_)
            WS_TRYV(internal_reserve(size));
        used_ = size;
        return {};
    }

    /**
     * Discard `size` bytes from the end of the buffer.
     * This operation does not deallocate memory, it only reduces the buffer size.
     * Parameter `size` MUST be less than or equal to the current buffer size.
     */
    inline void discard_end(size_t size) noexcept
    {
        assert(size <= used_ && "Buffer index out of bounds");
        used_ -= size;
    }

    /**
     * Append `size` bytes copied from `data`.
     * If required, the buffer is resized to accommodate the new data.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    inline expected<span<byte>, WSError> append(const byte* data, size_t size) noexcept
    {
        auto pos = this->size();
        auto new_pos = pos + size;
        if (new_pos > capacity_)
            WS_TRYV(internal_reserve(new_pos));
        std::memcpy(buffer_ + pos, data, size);
        used_ = new_pos;
        return span<byte>(buffer_ + pos, size);
    }

    /**
     * Append `size` uninitialized bytes to buffer.
     * This does not actually write anything to the buffer, it allocates memory if required.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    inline expected<span<byte>, WSError> append(size_t size) noexcept
    {
        auto pos = this->size();
        auto new_pos = pos + size;
        if (new_pos > capacity_)
            WS_TRYV(internal_reserve(new_pos));
        used_ = new_pos;
        return span<byte>(buffer_ + pos, size);
    }

    /**
     * Returns a span of bytes over the data written to the buffer.
     */
    [[nodiscard]] inline span<byte> data() noexcept
    {
        if (buffer_ == nullptr)
            return {};
        return span<byte>(buffer_, used_);
    }

private:
    [[nodiscard]] expected<void, WSError> internal_reserve(size_t size) noexcept
    {
        if (size > max_size_)
        {
            return WS_ERROR(
                buffer_error,
                std::format(
                    "Requested buffer size {} exceeds maximum allowed size of {} bytes",
                    size,
                    max_size_
                ),
                close_code::not_set
            );
        }

        // allocate new buffer, or resize existing one
        byte* newbuf = static_cast<byte*>(
            std::realloc(buffer_, std::max(static_cast<size_t>(1), size))
        );
        if (newbuf == nullptr)
        {
            return WS_ERROR(
                buffer_error,
                std::format("Failed to allocate buffer of size {}", size),
                close_code::not_set
            );
        }

        buffer_ = newbuf;
        capacity_ = size;
        used_ = std::min(used_, size);
        return {};
    }
};

/**
 * A guard class that automatically clears a buffer on destruction.
 * This is useful for clearing a buffer on every iteration of a loop.
 * Clearing means setting the buffer size to zero, but not deallocating the memory.
 * If a large message is received, the memory is not deallocated and can be reused.
 * Memory is only deallocated when the buffer is destroyed or `reset` is called.
 */
class BufferClearGuard
{
private:
    Buffer& buffer;

public:
    BufferClearGuard(Buffer& buffer) noexcept : buffer(buffer)
    {
    }
    ~BufferClearGuard() noexcept
    {
        buffer.clear();
    }

    // delete copy constructor and assignment operator
    BufferClearGuard(const BufferClearGuard&) = delete;
    BufferClearGuard& operator=(const BufferClearGuard&) = delete;
};

/**
 * A guard class that automatically resets a buffer on destruction.
 * This is useful for deallocating the buffer memory when it is no longer needed.
 * The buffer is reset to its initial state, i.e. the size is set to zero and memory is deallocated.
 */
class BufferResetGuard
{
private:
    Buffer& buffer;

public:
    BufferResetGuard(Buffer& buffer) noexcept : buffer(buffer)
    {
    }
    ~BufferResetGuard() noexcept
    {
        buffer.reset();
    }

    // delete copy constructor and assignment operator
    BufferResetGuard(const BufferResetGuard&) = delete;
    BufferResetGuard& operator=(const BufferResetGuard&) = delete;
};

static_assert(HasBufferOperations<Buffer>, "Buffer does not satisfy HasBufferOperations concept");

} // namespace ws_client
