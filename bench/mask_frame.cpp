// ./bench_mask_frame --benchmark_out_format=csv --benchmark_out=bench_mask_frame_x86.csv
// ./bench_mask_frame --benchmark_out_format=csv --benchmark_out=bench_mask_frame_arm.csv

#include <benchmark/benchmark.h>
#include <string>
#include <iostream>
#include <cstddef>
#include <span>
#include <cstdint>
#include <string_view>
#include <cstring>

#include "ws_client/MaskKey.hpp"
#include "cpu_utils.hpp"

namespace bm = benchmark;

using std::byte;
using std::span;

struct data
{
    byte *input;
    size_t len;
    uint32_t mask;
    bool misaligned{false};

    ~data()
    {
        if (misaligned)
            delete[] (--input);
        else
            delete[] input;
    }

    void misalign()
    {
        ++input;
        --len;
        misaligned = true;
    }
};

static data *get_data(size_t length)
{
    byte* input = new byte[length];
    data *dat = new data{input, length, 2342534534};

    // misalign input
    // dat->misalign();

    return dat;
}

using MaskFunctionPtr = void (*)(byte *, size_t, uint32_t);

template <MaskFunctionPtr func>
static void test(bm::State &state)
{
    auto length = state.range(0);
    set_cpu_affinity(2);

    data *dat = get_data(length);

    for (auto _ : state)
    {
        func(dat->input, dat->len, dat->mask);

        // prevent compiler optimizations
        benchmark::DoNotOptimize(dat->input[0]);
    }

    delete dat;
}

// ------------------------------------------------------

void mask_naive(byte *data, size_t len, uint32_t key)
{
    byte *key_bytes = reinterpret_cast<byte *>(&key);
    for (size_t i = 0; i < len; ++i)
        data[i] ^= key_bytes[i % 4];
}


/**
 * Mask data aligned to an arbitrary bytes boundary (template parameter `align`).
 * The mask function is passed as a parameter (template parameter `MaskFunc`),
 * which is called on each aligned chunk (of size `align`) with a pointer to the chunk.
 * Unaligned leading and trailing bytes are processed naively byte by byte.
 */
template <size_t align, typename MaskFunc>
void mask_aligned(byte *data, size_t len, uint32_t key, const MaskFunc mask_func)
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

void mask_uint64(byte *data, size_t len, uint32_t key)
{
    uint64_t key_64 = (static_cast<uint64_t>(key) << 32) | key;
    auto mask_fn = [&key_64](byte *data)
    {
        *reinterpret_cast<uint64_t *>(data) ^= key_64; //
    };
    mask_aligned<8>(data, len, key, mask_fn);
}

void mask_using_MaskKey(byte *data, size_t len, uint32_t key)
{
    ws_client::MaskKey mask_key(key);
    mask_key.mask(span<byte>(data, len));
}

#ifdef __SSE2__

#include <emmintrin.h>

void mask_sse2(byte *data, size_t len, uint32_t key)
{
    const __m128i key_128 = _mm_set1_epi32(key); // 128-bit vector with key repeated
    auto mask_fn = [&key_128](byte *data)
    {
        auto ptr = reinterpret_cast<__m128i *>(data);
        __m128i chunk = _mm_load_si128(ptr);
        chunk = _mm_xor_si128(chunk, key_128);
        _mm_store_si128(ptr, chunk);
    };
    mask_aligned<16>(data, len, key, mask_fn);
}

#endif

#ifdef __AVX2__

#include <immintrin.h>

void mask_avx2(byte *data, size_t len, uint32_t key)
{
    const __m256i key_256 = _mm256_set1_epi32(key); // 256-bit vector with key repeated
    auto mask_fn = [&key_256](byte *data)
    {
        auto ptr = reinterpret_cast<__m256i *>(data);
        __m256i chunk = _mm256_load_si256(ptr);
        chunk = _mm256_xor_si256(chunk, key_256);
        _mm256_store_si256(ptr, chunk);
    };
    mask_aligned<32>(data, len, key, mask_fn);
}

#endif


#ifdef __aarch64__

#include <arm_neon.h>

void mask_arm_neon(byte *data, size_t len, uint32_t key)
{
    // Duplicate the 32-bit key to all four parts of a 128-bit vector
    const uint32x4_t key_128 = ::vdupq_n_u32(key);

    auto mask_fn = [&key_128](byte *data) {
        // Load data into two 64-bit chunks (128 bits total)
        uint32x4_t chunk = ::vld1q_u32(reinterpret_cast<const uint32_t *>(data));

        // XOR the loaded data with the key vector
        chunk = ::veorq_u32(chunk, key_128);

        // Store the result back into memory
        ::vst1q_u32(reinterpret_cast<uint32_t *>(data), chunk);
    };
    mask_aligned<16>(data, len, key, mask_fn);
}

#endif

constexpr size_t max_len = 8 << 20;
constexpr size_t min_len = 8;
constexpr size_t multiplier = 4;
BENCHMARK(test<mask_naive>)->RangeMultiplier(multiplier)->Range(min_len, max_len);
BENCHMARK(test<mask_uint64>)->RangeMultiplier(multiplier)->Range(min_len, max_len);
BENCHMARK(test<mask_using_MaskKey>)->RangeMultiplier(multiplier)->Range(min_len, max_len);

#ifdef __SSE2__
BENCHMARK(test<mask_sse2>)->RangeMultiplier(multiplier)->Range(min_len, max_len);
#endif

#ifdef __AVX2__
BENCHMARK(test<mask_avx2>)->RangeMultiplier(multiplier)->Range(min_len, max_len);
#endif

#ifdef __aarch64__
BENCHMARK(test<mask_arm_neon>)->RangeMultiplier(multiplier)->Range(min_len, max_len);
#endif
