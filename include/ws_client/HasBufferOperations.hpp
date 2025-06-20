#pragma once

#include <expected>
#include <cstddef>
#include <span>
#include <concepts>

#include "ws_client/errors.hpp"

namespace ws_client
{
using byte = std::byte;

/**
 * Concept for buffer-like template type parameters.
 */
template <typename T>
concept HasBufferOperations = requires(T t, std::span<byte> buffer, const byte* data, size_t size) {
    /**
     * Returns a span of bytes over the data written to the buffer.
     */
    { t.data() } -> std::same_as<std::span<byte>>;

    /**
     * Get the number of bytes currently stored in the buffer.
     */
    { t.size() } -> std::same_as<size_t>;

    /**
     * Set the maximum allowed buffer size / capacity.
     */
    { t.set_max_size(size) } -> std::same_as<void>;

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
    { t.reserve(size) } -> std::same_as<std::expected<void, WSError>>;

    /**
     * Resize the buffer to `size` bytes.
     * The buffer data can then be accessed using the `data` method.
     * The allocated space is exactly `size` bytes after this operation.
     */
    { t.resize(size) } -> std::same_as<std::expected<void, WSError>>;

    /**
     * Get the current number of allocated bytes.
     * This is the actual memory size allocated for the buffer.
     * The buffer size can be smaller than the allocated memory size.
     */
    { t.allocated() } -> std::same_as<size_t>;

    /**
     * Discard `size` bytes from the end of the buffer.
     * This operation does not deallocate memory, it only reduces the buffer size.
     * Parameter `size` MUST be less than or equal to the current buffer size.
     */
    { t.discard_end(size) } -> std::same_as<void>;

    /**
     * Append `size` bytes copied from `data`.
     * If required, the buffer is resized to accommodate the new data.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    { t.append(data, size) } -> std::same_as<std::expected<std::span<byte>, WSError>>;

    /**
     * Append `size` uninitialized bytes to buffer.
     * This does not actually write anything to the buffer, it allocates memory if required.
     * Existing data in the buffer is preserved.
     * Returns added data region as a span of bytes.
     */
    { t.append(size) } -> std::same_as<std::expected<std::span<byte>, WSError>>;
};
} // namespace ws_client
