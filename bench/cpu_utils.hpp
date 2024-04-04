#pragma once

#include <cstdint>
#include <thread>
#include <pthread.h>
#include <iostream>

/**
 * Set the CPU affinity of the current thread.
 */
inline void set_cpu_affinity(int cpu_affinity)
{
    if (cpu_affinity == -1)
        return;
#if __APPLE__
        // no implementation for Apple systems
#else
    if (cpu_affinity > static_cast<int>(std::thread::hardware_concurrency()))
        std::cerr << "Invalid CPU affinity value: " + std::to_string(cpu_affinity) +
                                 " (max: " + std::to_string(std::thread::hardware_concurrency()) +
                                 ")" << std::endl;

    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu_affinity, &cpus);
    int res = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpus);
    if (res != 0)
        std::cerr << "Failed to set CPU affinity. Return code: " + std::to_string(res) << std::endl;
#endif
}
