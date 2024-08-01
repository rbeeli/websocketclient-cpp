#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <concepts>

#include "ws_client/utils/random.hpp"

#ifdef __SSE2__

// SSE2 SIMD instructions
#include <emmintrin.h>

#elif defined(__aarch64__)

// ARM NEON SIMD instructions
#include <arm_neon.h>

#endif

namespace ws_client
{
using std::byte;
using std::span;

/**
 * Masking key for masking and unmasking WebSocket frame payloads.
 * Uses XOR to mask/unmask. Optimized for 64-bit architectures.
 */
struct MaskKey
{
    uint32_t key{0};

    MaskKey() noexcept = default;

    explicit MaskKey(const uint32_t key) noexcept : key(key)
    {
    }

    /**
     * Masks a byte array with a 32 bit masking key by XORing the key with the data.
     * For better performance, the masking is performed in chunks.
     * 
     * Misaligned leading and trailing bytes are handled individually.
     * 
     * If supported, SSE2 or NEON SIMD instructions are used.
     * 
     * This implementation is up to 100x faster than a naive byte-by-byte
     * implementation for large payloads.
     */
    inline void mask(span<byte> data) const
    {
        mask_fn(data.data(), data.size(), this->key);
    }


    /**
     * Mask data aligned to an arbitrary bytes boundary (template parameter `align`).
     * The mask function is passed as a parameter (template parameter `MaskFunc`),
     * which is called on each aligned chunk (of size `align`) with a pointer to the chunk.
     * Unaligned leading and trailing bytes are processed naively byte by byte.
     */
    template <size_t align, typename MaskFunc>
    static void mask_aligned(byte* data, size_t len, uint32_t key, const MaskFunc mask_func)
    {
        byte* key_bytes = reinterpret_cast<byte*>(&key);

        // align data pointer to boundary
        auto ptr = reinterpret_cast<uintptr_t>(data);
        size_t unaligned = (ptr & (align - 1));
        if (unaligned)
            unaligned = align - unaligned;
        unaligned = unaligned > len ? len : unaligned;

        // processing leading bytes naively
        size_t i = 0;
        for (; i < unaligned; i++)
            data[i] ^= key_bytes[i & (sizeof(uint32_t) - 1)];

        // processing aligned chunks
        for (; i + align <= len; i += align)
            mask_func(data + i);

        // handling trailing bytes naively
        for (; i < len; ++i)
            data[i] ^= key_bytes[i & (sizeof(uint32_t) - 1)];
    }

#ifdef __SSE2__

    // SSE2 SIMD instructions

    static void mask_fn(byte* data, size_t len, uint32_t key)
    {
        const __m128i key_128 = _mm_set1_epi32(key); // 128-bit vector with key repeated
        auto mask_func = [&key_128](byte* data)
        {
            auto ptr = reinterpret_cast<__m128i*>(data);
            __m128i chunk = _mm_load_si128(ptr);
            chunk = _mm_xor_si128(chunk, key_128);
            _mm_store_si128(ptr, chunk);
        };
        mask_aligned<16>(data, len, key, mask_func);
    }

#elif defined(__aarch64__)

    // ARM NEON SIMD instructions

    static void mask_fn(byte* data, size_t len, uint32_t key)
    {
        // Duplicate the 32-bit key to all four parts of a 128-bit vector
        const uint32x4_t key_128 = ::vdupq_n_u32(key);

        auto mask_func = [&key_128](byte* data)
        {
            // Load data into two 64-bit chunks (128 bits total)
            uint32x4_t chunk = ::vld1q_u32(reinterpret_cast<const uint32_t*>(data));

            // XOR the loaded data with the key vector
            chunk = ::veorq_u32(chunk, key_128);

            // Store the result back into memory
            ::vst1q_u32(reinterpret_cast<uint32_t*>(data), chunk);
        };
        mask_aligned<16>(data, len, key, mask_func);
    }

#else

    // no SIMD instructions available, use 64 bit chunks implementation

    static void mask_fn(byte* data, size_t len, uint32_t key)
    {
        uint64_t key_64 = (static_cast<uint64_t>(key) << 32) | key;
        auto mask_func = [&key_64](byte* data)
        {
            *reinterpret_cast<uint64_t*>(data) ^= key_64; //
        };
        mask_aligned<8>(data, len, key, mask_func);
    }

#endif
};

/**
 * Concept for a MaskKey generator template type.
 * Used in `WebSocketClient` and `WebSocketClientAsync` to generate a new masking key for each frame.
 */
template <typename T>
concept HasMaskKeyOperator = requires(T t) {
    { t() } noexcept -> std::same_as<MaskKey>;
};

/**
 * Frame masking key generator using a static/constant value (never changes).
 * Useful for testing, but not recommended for production.
 */
struct ConstantMaskKeyGen
{
    uint32_t key;

    explicit ConstantMaskKeyGen(uint32_t key) noexcept : key(key)
    {
    }

    inline MaskKey operator()() const noexcept
    {
        return MaskKey(key);
    }
};

/**
 * Frame masking key generator using the xoshiro128+ pseudo-random number generator.
 * The seed can be specified in the constructor (optional).
 * This is NOT a cryptographically secure random number generator.
 */
struct DefaultMaskKeyGen
{
    xoshiro128p rng;

    explicit DefaultMaskKeyGen(uint64_t seed) noexcept : rng(xoshiro128p(seed))
    {
    }

    DefaultMaskKeyGen() noexcept : DefaultMaskKeyGen(0)
    {
    }

    inline MaskKey operator()() noexcept
    {
        return MaskKey(rng.next());
    }
};
} // namespace ws_client
