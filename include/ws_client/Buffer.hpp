#pragma once

#include <expected>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <span>
#include <concepts>
#include <cassert>

#include "ws_client/errors.hpp"

namespace ws_client
{
using std::byte;
using std::span;

/**
 * Concept for buffer-like template type parameters.
 */
template <typename T>
concept HasBufferOperations = requires(T t, span<byte> buffer, const byte* data, size_t len) {
    /**
     * Returns a span of bytes over the data written to the buffer.
     */
    { t.data() } -> std::same_as<span<byte>>;

    /**
     * Get the number of bytes currently stored in the buffer.
     */
    { t.size() } -> std::same_as<size_t>;

    /**
     * Set the maximum allowed buffer size / capacity.
     */
    { t.set_max_size(len) } -> std::same_as<void>;

    /**
     * Get the maximum allowed buffer size / capacity.
     */
    { t.max_size() } -> std::same_as<size_t>;

    /**
     * Check if buffer is empty, i.e. contains no data.
     */
    { t.empty() } -> std::same_as<bool>;

    /**
     * Reserve space for at least `size` bytes in the buffer.
     * Only performs allocation if the requested size is greater than the current capacity.
     */
    { t.reserve(len) } -> std::same_as<expected<void, WSError>>;

    /**
     * Get the current number of allocated bytes.
     * This is the actual memory size allocated for the buffer.
     * The buffer size can be smaller than the allocated memory size.
     */
    { t.allocated() } -> std::same_as<size_t>;

    /**
     * Resize the buffer to `size` bytes.
     * The buffer data can then be accessed using the `data` method.
     * The allocated space is exactly `size` bytes after this operation.
     */
    { t.resize(len) } -> std::same_as<expected<void, WSError>>;

    /**
     * Discard `size` bytes from the end of the buffer.
     * This operation does not deallocate memory, it only reduces the buffer size.
     * Parameter `size` MUST be less than or equal to the current buffer size.
     */
    { t.discard_end(len) } -> std::same_as<void>;

    /**
     * Append `len` bytes copied from `data`.
     * If required, the buffer is resized to accommodate the new data.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    { t.append(data, len) } -> std::same_as<expected<span<byte>, WSError>>;

    /**
     * Append `len` uninitialized bytes to buffer.
     * This does not actually write anything to the buffer, it allocates memory if required.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    { t.append(len) } -> std::same_as<expected<span<byte>, WSError>>;
};

/**
 * A simple buffer class for storing binary data, similar to `std::vector<byte>`.
 * The buffer can be resized and data can be appended to it.
 * 
 * The default maximum size is 16 MB, use `set_max_size` to adjust it.
 */
class Buffer
{
private:
    size_t max_size_;
    size_t capacity;
    size_t used;
    byte* buffer = nullptr;

public:
    /**
     * Default maximum buffer size.
     * If not specified, the buffer will be limited to 16 MB by default.
     */
    static constexpr size_t default_max_size = 16 * 1024 * 1024;

    explicit Buffer(size_t max_size = default_max_size) noexcept
        : max_size_(max_size), capacity(0), used(0)
    {
    }

    ~Buffer() noexcept
    {
        std::free(this->buffer);
        this->buffer = nullptr;
    }

    // delete copy constructor and copy assignment operator
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    // move constructor and move assignment operator
    Buffer(Buffer&& other) noexcept
        : max_size_(other.max_size_),
          capacity(other.capacity),
          used(other.used),
          buffer(other.buffer)
    {
        other.buffer = nullptr;
        other.capacity = 0;
        other.used = 0;
    }
    Buffer& operator=(Buffer&& other) noexcept
    {
        if (this != &other)
        {
            std::free(this->buffer);
            this->max_size_ = other.max_size_;
            this->capacity = other.capacity;
            this->used = other.used;
            this->buffer = other.buffer;
            other.buffer = nullptr;
            other.capacity = 0;
            other.used = 0;
        }
        return *this;
    }

    /**
     * Get the number of bytes currently stored in the buffer.
     */
    [[nodiscard]] inline size_t size() const noexcept
    {
        return this->used;
    }

    /**
     * Get the current number of allocated bytes.
     * This is the actual memory size allocated for the buffer.
     * The buffer size can be smaller than the allocated memory size.
     */
    [[nodiscard]] inline size_t allocated() const noexcept
    {
        return this->capacity;
    }

    /**
     * Clears the buffer data.
     * Does not deallocate the buffer or shrink memory usage.
     * Use `reset` to resize the physical buffer and reduce memory usage.
     */
    inline void clear() noexcept
    {
        this->used = 0;
    }

    /**
     * Deallocate the buffer and reset its state.
     */
    inline void reset() noexcept
    {
        std::free(this->buffer);
        this->buffer = nullptr;
        this->capacity = 0;
        this->used = 0;
    }

    /**
     * Check if buffer is empty, i.e. contains no data.
     */
    [[nodiscard]] inline bool empty() const noexcept
    {
        return this->used == 0;
    }

    /**
     * Check if buffer is full, meaning it has reached
     * the maximum allowed size `max_size`.
     */
    [[nodiscard]] inline bool full() const noexcept
    {
        return this->used == this->max_size_;
    }

    [[nodiscard]] inline byte& at(size_t pos) noexcept
    {
        assert(pos < this->used && "Buffer index out of bounds");
        return this->buffer[pos];
    }

    [[nodiscard]] inline byte& operator[](size_t pos) noexcept
    {
        assert(pos < this->used && "Buffer index out of bounds");
        return this->buffer[pos];
    }

    /**
     * Set the maximum allowed buffer size / capacity.
     */
    void set_max_size(size_t max_size) noexcept
    {
        this->max_size_ = max_size;
    }

    /**
     * Get the maximum allowed buffer size / capacity.
     */
    [[nodiscard]] size_t max_size() const noexcept
    {
        return this->max_size_;
    }

    /**
     * Reserve space for at least `size` bytes in the buffer.
     * Only performs allocation if the requested size is greater than the current capacity.
     */
    [[nodiscard]] inline expected<void, WSError> reserve(size_t size) noexcept
    {
        if (size > this->capacity)
            WS_TRYV(this->internal_reserve(size));
        return {};
    }

    /**
     * Resize the buffer to `size` bytes.
     * The buffer data can then be accessed using the `data` method.
     * The allocated space is exactly `size` bytes after this operation.
     */
    [[nodiscard]] inline expected<void, WSError> resize(size_t size) noexcept
    {
        if (size != this->capacity)
            WS_TRYV(this->internal_reserve(size));
        this->used = size;
        return {};
    }

    /**
     * Discard `size` bytes from the end of the buffer.
     * This operation does not deallocate memory, it only reduces the buffer size.
     * Parameter `size` MUST be less than or equal to the current buffer size.
     */
    inline void discard_end(size_t size) noexcept
    {
        assert(size <= this->used && "Buffer index out of bounds");
        this->used -= size;
    }

    /**
     * Append `len` bytes copied from `data`.
     * If required, the buffer is resized to accommodate the new data.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    [[nodiscard]] inline expected<span<byte>, WSError> append(const byte* data, size_t len) noexcept
    {
        auto pos = size();
        auto new_pos = pos + len;
        if (new_pos > this->capacity)
            WS_TRYV(this->internal_reserve(new_pos));
        std::memcpy(this->buffer + pos, data, len);
        this->used = new_pos;
        return span<byte>(this->buffer + pos, len);
    }

    /**
     * Append `len` uninitialized bytes to buffer.
     * This does not actually write anything to the buffer, it allocates memory if required.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    [[nodiscard]] inline expected<span<byte>, WSError> append(size_t len) noexcept
    {
        auto pos = size();
        auto new_pos = pos + len;
        if (new_pos > this->capacity)
            WS_TRYV(this->internal_reserve(new_pos));
        this->used = new_pos;
        return span<byte>(this->buffer + pos, len);
    }

    /**
     * Returns a span of bytes over the data written to the buffer.
     */
    [[nodiscard]] inline span<byte> data() noexcept
    {
        if (this->buffer == nullptr)
            return {};
        return span<byte>(this->buffer, this->used);
    }

private:
    [[nodiscard]] expected<void, WSError> internal_reserve(size_t size) noexcept
    {
        if (size > this->max_size_)
        {
            return WS_ERROR(
                BUFFER_ERROR,
                "Requested buffer size " + std::to_string(size) +
                    " exceeds maximum allowed size of " + std::to_string(this->max_size_) +
                    " bytes",
                NOT_SET
            );
        }

        // allocate new buffer, or resize existing one
        byte* newbuf = static_cast<byte*>(
            std::realloc(this->buffer, std::max(static_cast<size_t>(1), size))
        );
        if (newbuf == nullptr)
        {
            return WS_ERROR(
                BUFFER_ERROR, "Failed to allocate buffer of size " + std::to_string(size), NOT_SET
            );
        }

        this->buffer = newbuf;
        this->capacity = size;
        this->used = std::min(this->used, size);
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
