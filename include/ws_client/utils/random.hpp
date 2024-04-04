// Based on: https://prng.di.unimi.it/xoshiro128plus.c

#pragma once

/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

#include <chrono>
#include <cstdint>

/* This is xoshiro128+ 1.0, our best and fastest 32-bit generator for 32-bit
   floating-point numbers. We suggest to use its upper bits for
   floating-point generation, as it is slightly faster than xoshiro128**.
   It passes all tests we are aware of except for
   linearity tests, as the lowest four bits have low linear complexity, so
   if low linear complexity is not considered an issue (as it is usually
   the case) it can be used to generate 32-bit outputs, too.

   We suggest to use a sign test to extract a random Boolean value, and
   right shifts to extract subsets of bits.

   The state must be seeded so that it is not everywhere zero. */

/*  Written in 2015 by Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

/**
 * Xoshiro128+ random number generator wrapper class
 * around the original C implementation.
 * 
 * Benchmarks show that this implementation is about 3-10x faster than std::mt19937.
 */
struct xoshiro128p
{
    uint32_t s[4];

    xoshiro128p()
    {
        // seed with current time
        uint64_t seed = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        uint64_t z = seed_splitmix64(seed);
        s[0] = static_cast<uint32_t>(z);
        s[1] = static_cast<uint32_t>(z >> 32);
        z = seed_splitmix64(z);
        s[2] = static_cast<uint32_t>(z);
        s[3] = static_cast<uint32_t>(z >> 32);
    }

    explicit xoshiro128p(uint64_t seed)
    {
        uint64_t z = seed_splitmix64(seed);
        s[0] = static_cast<uint32_t>(z);
        s[1] = static_cast<uint32_t>(z >> 32);
        z = seed_splitmix64(z);
        s[2] = static_cast<uint32_t>(z);
        s[3] = static_cast<uint32_t>(z >> 32);
    }

    static uint64_t seed_splitmix64(uint64_t x)
    {
        uint64_t z = (x += 0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    static inline uint32_t rotl(const uint32_t x, int k)
    {
        return (x << k) | (x >> (32 - k));
    }

    /**
     * Returns a random 32-bit unsigned integer.
     */
    inline uint32_t next() noexcept
    {
        const uint32_t result = s[0] + s[3];

        const uint32_t t = s[1] << 9;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;

        s[3] = rotl(s[3], 11);

        return result;
    }

    /**
     * This is the jump function for the generator. It is equivalent
     * to 2^64 calls to next(); it can be used to generate 2^64
     * non-overlapping subsequences for parallel computations.
     */
    inline void jump() noexcept
    {
        static const uint32_t JUMP[] = {0x8764000b, 0xf542d2d3, 0x6fa035c3, 0x77f2db5b};

        uint32_t s0 = 0;
        uint32_t s1 = 0;
        uint32_t s2 = 0;
        uint32_t s3 = 0;
        for (auto jump_value : JUMP)
        {
            for (int b = 0; b < 32; b++)
            {
                if (jump_value & (UINT32_C(1) << b))
                {
                    s0 ^= s[0];
                    s1 ^= s[1];
                    s2 ^= s[2];
                    s3 ^= s[3];
                }
                this->next();
            }
        }
        s[0] = s0;
        s[1] = s1;
        s[2] = s2;
        s[3] = s3;
    }

    /**
     * This is the long-jump function for the generator. It is equivalent to
     * 2^96 calls to next(); it can be used to generate 2^32 starting points,
     * from each of which jump() will generate 2^32 non-overlapping
     * subsequences for parallel distributed computations.
     */
    inline void long_jump(void) noexcept
    {
        static const uint32_t LONG_JUMP[] = {0xb523952e, 0x0b6f099f, 0xccf5a0ef, 0x1c580662};

        uint32_t s0 = 0;
        uint32_t s1 = 0;
        uint32_t s2 = 0;
        uint32_t s3 = 0;
        for (auto jump_value : LONG_JUMP)
        {
            for (int b = 0; b < 32; b++)
            {
                if (jump_value & UINT32_C(1) << b)
                {
                    s0 ^= s[0];
                    s1 ^= s[1];
                    s2 ^= s[2];
                    s3 ^= s[3];
                }
                this->next();
            }
        }
        s[0] = s0;
        s[1] = s1;
        s[2] = s2;
        s[3] = s3;
    }
};
