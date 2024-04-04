#include <benchmark/benchmark.h>
#include <string>
#include <variant>

#include "cpu_utils.hpp"

namespace bm = benchmark;

#define BENCH(X) BENCHMARK(X)->MinWarmUpTime(0.1)->MinTime(0.5);

size_t __attribute__ ((noinline)) get_size_t(size_t s)
{
    return s+1;
}

std::variant<size_t, bool> __attribute__ ((noinline)) get_variant(size_t s)
{
    return s+1;
}

static void test_get_size_t(bm::State &state)
{
    set_cpu_affinity(2);
    size_t c = 0;
    for (auto _ : state)
    {
        auto res = get_size_t(c);
        if (res == 0)
            c++;

        // Prevent compiler optimizations
        benchmark::DoNotOptimize(res);
    }

    benchmark::DoNotOptimize(c);
}

static void test_get_variant(bm::State &state)
{
    set_cpu_affinity(2);
    size_t c = 0;
    for (auto _ : state)
    {
        auto res = get_variant(c);
        if (std::holds_alternative<bool>(res))
            c++;

        // Prevent compiler optimizations
        benchmark::DoNotOptimize(res);
    }

    benchmark::DoNotOptimize(c);
}

BENCH(test_get_size_t);
BENCH(test_get_variant);
