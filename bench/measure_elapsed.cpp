#include <benchmark/benchmark.h>
#include <chrono>
#include <ctime>
#include <time.h>

#ifdef __x86_64__
#include <x86intrin.h>
#endif

// Benchmark for std::chrono
static void BM_Chrono(benchmark::State& state) {
    for (auto _ : state) {
        auto start = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        benchmark::DoNotOptimize(end - start);
    }
}

static void BM_Chrono_steady_clock(benchmark::State& state) {
    for (auto _ : state) {
        auto start = std::chrono::steady_clock::now();
        auto end = std::chrono::steady_clock::now();
        benchmark::DoNotOptimize(end - start);
    }
}

// Benchmark for clock()
static void BM_Clock(benchmark::State& state) {
    for (auto _ : state) {
        clock_t start = clock();
        clock_t end = clock();
        benchmark::DoNotOptimize(end - start);
    }
}

// Benchmark for clock_gettime()
static void BM_ClockGettime(benchmark::State& state) {
    for (auto _ : state) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        benchmark::DoNotOptimize(end.tv_nsec - start.tv_nsec);
    }
}

#ifdef __x86_64__
// Benchmark for rdtsc
static void BM_Rdtsc(benchmark::State& state) {
    for (auto _ : state) {
        unsigned long long start = __rdtsc();
        unsigned long long end = __rdtsc();
        benchmark::DoNotOptimize(end - start);
    }
}
#endif

BENCHMARK(BM_Chrono);
BENCHMARK(BM_Chrono_steady_clock);
BENCHMARK(BM_Clock);
BENCHMARK(BM_ClockGettime);
#ifdef __x86_64__
BENCHMARK(BM_Rdtsc);
#endif
