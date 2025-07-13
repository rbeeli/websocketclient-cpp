#pragma once

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <span>
#include <algorithm>
#include <type_traits>
#include <new>

namespace ws_client
{
/**
 * Circular buffer data structure for primitive / trivially copyable types.
 * 
 * The buffer is a fixed-size array that wraps around when it reaches the end.
 * The buffer can be used to store and retrieve items in a FIFO manner.
 * The buffer is not thread-safe and should be used in a single-threaded context only.
 * It is not allowed to push more items than the buffer can store,
 * the user MUST check the available space before pushing.
 * Memory is allocated using aligned alloc.
 */
template <typename T>
    requires std::is_trivially_copyable_v<T>
class CircularBuffer
{
private:
    struct AlignedDelete
    {
        void operator()(void* p) const noexcept
        {
            ::operator delete[](p, std::align_val_t{alignof(T)});
        }
    };
    std::unique_ptr<T[], AlignedDelete> buffer_{nullptr};

    size_t head_{0};
    size_t tail_{0};
    bool full_{false};
    size_t capacity_{0};

public:
    explicit CircularBuffer(const size_t capacity) noexcept
        : buffer_(
              static_cast<T*>(::operator new[](capacity * sizeof(T), std::align_val_t{alignof(T)}))
          ),
          capacity_(capacity)
    {
        assert(
            capacity != 0 && (capacity & (capacity - 1)) == 0 &&
            "CircularBuffer capacity must be a power of two and non-zero"
        );
        assert(buffer_ && "CircularBuffer aligned allocation failed");
    }

    /**
     * Push single item onto buffer.
     */
    void push(const T& data) noexcept
    {
        assert(!full() && "CircularBuffer is full");

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
        assert(len <= available() && "CircularBuffer is full");

        T* buf = buffer_.get();

        // perform the copy in two steps if necessary due to wrap-around
        size_t first_copy_n = std::min(len, capacity_ - head_);
        std::copy(src, src + first_copy_n, buf + head_);
        len -= first_copy_n;
        head_ += first_copy_n;

        if (len > 0)
        {
            // wrap around and copy rest
            std::copy(src + first_copy_n, src + first_copy_n + len, buf);
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
    inline void push(std::span<const T> src) noexcept
    {
        push(src.data(), src.size());
    }

    /**
     * Pop single item from buffer.
     * Returns false if buffer is empty, otherwise true.
     */
    [[nodiscard]] bool pop(T& data) noexcept
    {
        if (empty())
            return false;

        T* buf = buffer_.get();

        data = buf[tail_];
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

        assert(len <= size() && "CircularBuffer does not contain enough data");

        // copy the first part
        size_t first_copy_n = std::min(len, capacity_ - tail_);

        T* buf = buffer_.get();

        std::copy(buf + tail_, buf + tail_ + first_copy_n, dest);
        tail_ += first_copy_n;
        len -= first_copy_n;

        // wrap around if reached the end of the buffer
        tail_ &= capacity_ - 1;

        // check if there's more to copy due to wrap-around
        if (len > 0)
        {
            std::copy(buf, buf + len, dest + first_copy_n);
            tail_ = len;
        }

        full_ = false;
    }

    /**
     * Pop multiple items from buffer.
     */
    inline void pop(std::span<T> dest) noexcept
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
    [[nodiscard]] inline std::span<T> available_as_contiguous_span() noexcept
    {
        T* buf = buffer_.get();

        if (full_)
            return {buf + head_, static_cast<size_t>(0)};

        if (head_ >= tail_)
            return {buf + head_, capacity_ - head_}; // normal case

        return {buf + head_, tail_ - head_}; // wrapped case
    }

    /**
     * Get span over the contiguous used items in the buffer.
     * The span can be used to directly read from the buffer.
     * To discard the read items, the tail pointer must be moved using `move_tail`.
     * 
     * Note that due to the wrap-around, the span might be shorter than
     * the used space in the buffer.
    */
    [[nodiscard]] inline std::span<T> used_as_contiguous_span() noexcept
    {
        T* buf = buffer_.get();

        if (empty())
            return {buf, static_cast<size_t>(0)};

        if (full_)
            return {buf + tail_, capacity_ - tail_};

        if (head_ >= tail_)
            return {buf + tail_, head_ - tail_}; // normal case

        return {buf + tail_, capacity_ - tail_}; // wrapped
    }

    /**
     * Moves the head (write) pointer by `len` positions.
     * This is useful when writing directly to the buffer
     * using the available_as_contiguous_span method.
     */
    inline void move_head(size_t len) noexcept
    {
        assert(len <= available() && "Cannot move head, CircularBuffer (almost) full");
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
        assert(len <= size() && "CircularBuffer does not contain enough data to move tail");
        tail_ += len;
        tail_ &= capacity_ - 1;
        full_ = false;
    }

    /**
     * Get single item from buffer without removing it.
     * This operation does not change the state of the buffer.
     * 
     *
     * @return Returns nullptr if buffer is empty, or pointer to element of type `T`.
     */
    [[nodiscard]] inline const T* peek() const noexcept
    {
        if (empty())
            return nullptr;
        T* buf = buffer_.get();
        return buf + tail_;
    }

    /**
     * Accesses the element at the given index in a circular manner.
     * The index is relative to the oldest element in the buffer.
     *
     * @param index The index of the element to access.
     */
    [[nodiscard]] inline T& operator[](size_t index)
    {
        assert(index < size() && "CircularBuffer index out of bounds");
        T* buf = buffer_.get();
        size_t ix = tail_ + index;
        ix &= capacity_ - 1;
        return buf[ix];
    }

    /**
     * Accesses the element at the given index in a circular manner.
     * The index is relative to the oldest element in the buffer.
     *
     * @param index The index of the element to access.
     */
    [[nodiscard]] inline const T& operator[](size_t index) const
    {
        assert(index < size() && "CircularBuffer index out of bounds");
        T* buf = buffer_.get();
        size_t ix = tail_ + index;
        ix &= capacity_ - 1;
        return buf[ix];
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
