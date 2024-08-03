#pragma once

#include <cassert>
#include <cstdint>
#include <span>
#include <algorithm>
#include <cstdlib>
#include <type_traits>

namespace ws_client
{
using std::span;

/**
 * Circular buffer data structure for primitive / trivially copyable types.
 * 
 * The buffer is a fixed-size array that wraps around when it reaches the end.
 * The buffer can be used to store and retrieve items in a FIFO manner.
 * The buffer is not thread-safe and should be used in a single-threaded context only.
 * It is not allowed to push more items than the buffer can store,
 * the user MUST check the available space before pushing.
 * Memory is allocated using `std::malloc`.
 */
template <typename T>
    requires std::is_trivially_copyable_v<T>
class CircularBuffer
{
private:
    T* buffer_;
    size_t head_;
    size_t tail_;
    bool full_;
    size_t capacity_;

public:
    explicit CircularBuffer(const size_t capacity) noexcept
        : head_(0), tail_(0), full_(false), capacity_(capacity)
    {
        // ensure power-of-two capacity
        assert((capacity & (capacity - 1)) == 0 && "Capacity must be a power of two");

        // allocate buffer
        buffer_ = reinterpret_cast<T*>(std::malloc(capacity * sizeof(T)));
        assert(buffer_ != nullptr && "Failed to allocate CircularBuffer buffer");
    }

    ~CircularBuffer() noexcept
    {
        if (buffer_ != nullptr)
        {
            std::free(buffer_);
            buffer_ = nullptr;
        }
    }

    // disable copy
    CircularBuffer(const CircularBuffer&) = delete;
    CircularBuffer& operator=(const CircularBuffer&) = delete;

    // enable move
    CircularBuffer(CircularBuffer&& other) noexcept
        : buffer_(other.buffer_),
          head_(other.head_),
          tail_(other.tail_),
          full_(other.full_),
          capacity_(other.capacity_)
    {
        other.buffer_ = nullptr;
        other.capacity_ = 0;
        other.head_ = 0;
        other.tail_ = 0;
        other.full_ = false;
    }
    CircularBuffer& operator=(CircularBuffer&& other) noexcept
    {
        if (this != &other)
        {
            if (buffer_ != nullptr)
                std::free(buffer_);

            buffer_ = other.buffer_;
            capacity_ = other.capacity_;
            head_ = other.head_;
            tail_ = other.tail_;
            full_ = other.full_;

            other.buffer_ = nullptr;
            other.capacity_ = 0;
            other.head_ = 0;
            other.tail_ = 0;
            other.full_ = false;
        }
        return *this;
    }

    /**
     * Push single item onto buffer.
     */
    void push(const T& data) noexcept
    {
        // check space left in buffer
        assert(!full() && "Buffer is full");

        buffer_[head_] = data;
        ++head_;

        // wrap around if we reached the end of the buffer
        head_ &= capacity_ - 1;

        // check if buffer is full after the push
        full_ = head_ == tail_;
    }

    /**
     * Push multiple items onto buffer.
     * The buffer must have enough space to store all items.
     */
    void push(const T* src, size_t len) noexcept
    {
        // check space left in buffer
        assert(len <= available() && "Buffer is full");

        // perform the copy in two steps if necessary due to wrap-around
        size_t first_copy_n = std::min(len, capacity_ - head_);
        std::copy(src, src + first_copy_n, buffer_ + head_);
        len -= first_copy_n;
        head_ += first_copy_n;

        if (len > 0)
        {
            // wrap around and copy rest
            std::copy(src + first_copy_n, src + first_copy_n + len, buffer_);
            head_ = len;
        }
        else
        {
            // wrap around if we reached the end of the buffer
            head_ &= capacity_ - 1;
        }

        // check if buffer is full after the push
        full_ = head_ == tail_;
    }

    /**
     * Push items onto buffer.
     */
    inline void push(span<const T> src) noexcept
    {
        push(src.data(), src.size());
    }

    /**
     * Pop single item from buffer.
     * Returns false if buffer is empty, otherwise true.
     */
    bool pop(T& data) noexcept
    {
        if (empty())
            return false;

        data = buffer_[tail_];
        tail_++;

        // wrap around if we reached the end of the buffer
        tail_ &= capacity_ - 1;

        full_ = false;

        return true;
    }

    /**
     * Pop multiple items from buffer.
     * The items are copied to dest and removed from the buffer.
     * Cannot pop more items than available in the buffer.
     */
    void pop(T* dest, size_t len) noexcept
    {
        if (len == 0 || empty())
            return;

        // check not reading more than available
        assert(len <= size() && "Buffer does not contain enough data");

        // copy the first part
        size_t first_copy_n = std::min(len, capacity_ - tail_);

        std::copy(buffer_ + tail_, buffer_ + tail_ + first_copy_n, dest);
        tail_ += first_copy_n;
        len -= first_copy_n;

        // wrap around if reached the end of the buffer
        tail_ &= capacity_ - 1;

        // check if there's more to copy due to wrap-around
        if (len > 0)
        {
            std::copy(buffer_, buffer_ + len, dest + first_copy_n);
            tail_ = len;
        }

        full_ = false;
    }

    /**
     * Pop multiple items from buffer.
     */
    inline void pop(span<T> dest) noexcept
    {
        pop(dest.data(), dest.size());
    }

    /**
     * Check if buffer is empty.
     */
    [[nodiscard]] inline bool empty() const noexcept
    {
        return head_ == tail_ && !full_;
    }

    /**
     * Check if buffer is full.
     */
    [[nodiscard]] inline bool full() const noexcept
    {
        return full_;
    }

    /**
     * Reset buffer to empty state.
     */
    inline void clear() noexcept
    {
        head_ = 0;
        tail_ = 0;
        full_ = false;
    }

    /**
     * Get number of items stored in buffer.
     */
    [[nodiscard]] inline size_t size() const noexcept
    {
        if (!full_)
        {
            if (head_ < tail_)
                return capacity_ + head_ - tail_;
            return head_ - tail_;
        }
        return capacity_;
    }

    /**
     * Get number of items that can be stored in buffer.
     */
    [[nodiscard]] inline size_t available() const noexcept
    {
        return capacity_ - size();
    }

    /**
     * Get span over the contiguous available items in the buffer.
     * The span can be used to directly write to the buffer,
     * but the head pointer must be moved after writing using `move_head`.
     * 
     * Note that due to the wrap-around, the span might be shorter than
     * the available space in the buffer.
     */
    [[nodiscard]] inline span<T> available_as_contiguous_span() noexcept
    {
        if (head_ >= tail_)
            return span<T>(buffer_ + head_, capacity_ - head_);
        return span<T>(buffer_ + head_, tail_ - head_);
    }

    /**
     * Get span over the contiguous used items in the buffer.
     * The span can be used to directly read from the buffer.
     * To discard the read items, the tail pointer must be moved using `move_tail`.
     * 
     * Note that due to the wrap-around, the span might be shorter than
     * the used space in the buffer.
    */
    [[nodiscard]] inline span<T> used_as_contiguous_span() noexcept
    {
        if (head_ >= tail_)
            return span<T>(buffer_ + tail_, head_ - tail_);
        return span<T>(buffer_ + tail_, capacity_ - tail_);
    }

    /**
     * Moves the head (write) pointer by `len` positions.
     * This is useful when writing directly to the buffer
     * using the available_as_contiguous_span method.
     */
    inline void move_head(size_t len) noexcept
    {
        // check space left in buffer
        assert(len <= available() && "Cannot move head, buffer (almost) full");
        head_ += len;
        head_ &= capacity_ - 1;
        full_ = head_ == tail_;
    }

    /**
     * Moves the tail (read) pointer by `len` positions.
     * This is useful when reading directly from the buffer
     * and removing data from the beginning of the buffer.
     */
    inline void move_tail(size_t len) noexcept
    {
        // check not reading more than available
        assert(len <= size() && "Buffer does not contain enough data to move tail");
        tail_ += len;
        tail_ &= capacity_ - 1;
        full_ = false;
    }

    /**
     * Get single item from buffer without removing it from it.
     * This operation does not change the state of the buffer.
     *
     * @return True if buffer is not empty and item was copied to data.
     */
    inline bool peek(T& data) const noexcept
    {
        bool data_updated = false;
        if (!empty())
        {
            data = buffer_[tail_];
            data_updated = true;
        }
        return data_updated;
    }

    /**
     * Accesses the element at the given index in a circular manner.
     * The index is relative to the oldest element in the buffer.
     *
     * @param index The index of the element to access.
     */
    [[nodiscard]] inline T& operator[](size_t index)
    {
        assert(index < size() && "Index out of bounds");
        size_t ix = tail_ + index;
        ix &= capacity_ - 1;
        return buffer_[ix];
    }

    /**
     * Accesses the element at the given index in a circular manner.
     * The index is relative to the oldest element in the buffer.
     *
     * @param index The index of the element to access.
     */
    [[nodiscard]] inline const T& operator[](size_t index) const
    {
        assert(index < size() && "Index out of bounds");
        size_t ix = tail_ + index;
        ix &= capacity_ - 1;
        return buffer_[ix];
    }

    /**
     * Get the maximum number of items that can be stored in the buffer.
     */
    [[nodiscard]] inline size_t capacity() const noexcept
    {
        return capacity_;
    }
};

} // namespace ws_client
