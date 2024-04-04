#include <benchmark/benchmark.h>
#include <random>

#include "cpu_utils.hpp"
#include "ws_client/utils/random.hpp"

namespace bm = benchmark;

static void test_std_random(bm::State& state)
{
    set_cpu_affinity(2);

    std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<uint32_t> distr(0, UINT32_MAX);

    for (auto _ : state)
    {
        uint32_t rnd = distr(generator);

        // Prevent compiler optimizations
        benchmark::DoNotOptimize(rnd);
    }
}

static void test_xoshiro128p(bm::State& state)
{
    set_cpu_affinity(2);

    xoshiro128p rng;

    for (auto _ : state)
    {
        uint32_t rnd = rng.next();

        // Prevent compiler optimizations
        benchmark::DoNotOptimize(rnd);
    }
}

BENCHMARK(test_std_random);
BENCHMARK(test_xoshiro128p);
