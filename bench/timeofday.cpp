#include <benchmark/benchmark.h>
#include <chrono>
#include <time.h>

#include "cpu_utils.hpp"

namespace bm = benchmark;

static void test_c_gettimeofday(bm::State& state)
{
    set_cpu_affinity(2);

    for (auto _ : state)
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        time_t seconds = ts.tv_sec % 86400;
        auto hour = seconds / 3600;
        auto minute = (seconds % 3600) / 60;
        auto second = seconds % 60;
        auto us = ts.tv_nsec / 1000;
        
        // Prevent compiler optimizations
        benchmark::DoNotOptimize(hour);
        benchmark::DoNotOptimize(minute);
        benchmark::DoNotOptimize(second);
        benchmark::DoNotOptimize(us);
    }
}

static void test_cpp_system_clock(bm::State& state)
{
    set_cpu_affinity(2);

    for (auto _ : state)
    {
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) %
                  std::chrono::seconds(1);

        // Prevent compiler optimizations
        benchmark::DoNotOptimize(now_t);
        benchmark::DoNotOptimize(us);
    }
}

BENCHMARK(test_c_gettimeofday);
BENCHMARK(test_cpp_system_clock);
