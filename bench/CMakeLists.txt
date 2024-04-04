find_package(benchmark REQUIRED)

add_executable(bench_mask_frame mask_frame.cpp)
add_executable(bench_variant variant.cpp)
add_executable(bench_timeofday timeofday.cpp)
add_executable(bench_random random.cpp)

target_link_libraries(bench_mask_frame PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    websocketclient)

target_link_libraries(bench_variant PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    websocketclient)

target_link_libraries(bench_timeofday PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    websocketclient)

target_link_libraries(bench_random PRIVATE
    benchmark::benchmark
    benchmark::benchmark_main
    websocketclient)
