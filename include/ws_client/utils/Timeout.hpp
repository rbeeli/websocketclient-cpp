#pragma once

#include <sys/time.h>
#include <cassert>
#include <chrono>

namespace ws_client
{
using namespace std::chrono_literals;

/**
 * Utility class to update a timeout by incorporating the elapsed time.
 * The start time is initialized to the current time.
 *
 * Template Parameters:
 * DT - Duration type, defaults to milliseconds
 * ClockT - Clock type, defaults to steady_clock for monotonic time measurement
 */
template <
    class DT = std::chrono::milliseconds, //
    class ClockT = std::chrono::steady_clock>
class Timeout
{
    const ClockT::time_point start_;
    const DT timeout_;

public:
    /**
     * Default constructor.
     * Initializes the start time to the current time.
     */
    explicit Timeout(const DT timeout) noexcept //
        : start_(ClockT::now()), timeout_(timeout)
    {
        assert(timeout_ > DT::zero() && "timeout must be positive and non-zero");
    }

    /**
     * Constructor with a custom start time.
     */
    explicit Timeout(const DT timeout, const ClockT::time_point start) noexcept //
        : start_(start), timeout_(timeout)
    {
        assert(timeout_ > DT::zero() && "timeout must be positive and non-zero");
    }

    /**
     * Returns the start time.
     */
    [[nodiscard]] inline ClockT::time_point start() const noexcept
    {
        return start_;
    }

    /**
     * Returns the total timeout duration.
     */
    [[nodiscard]] inline DT timeout() const noexcept
    {
        return timeout_;
    }

    /**
     * Returns the elapsed time since the start time.
     */
    template <class T = DT>
    [[nodiscard]] inline auto elapsed() const noexcept
    {
        return duration_cast<T>(ClockT::now() - start_);
    }

    /**
     * Returns the remaining time until the timeout is reached.
     */
    template <class T = DT>
    [[nodiscard]] inline auto remaining() const noexcept
    {
        auto elap = elapsed<T>();
        if (elap >= timeout_)
            return T::zero();
        return timeout_ - elap;
    }

    /**
     * Returns the remaining time as a `timeval` struct (see <sys/time.h>).
     */
    [[nodiscard]] inline timeval remaining_timeval() const noexcept
    {
        auto rem = remaining();
        struct timeval tv;
        tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(rem).count();
        tv.tv_usec = std::chrono::duration_cast<std::chrono::microseconds>(rem % 1s).count();
        return tv;
    }

    /**
     * Returns true if the timeout has been reached.
     */
    [[nodiscard]] inline bool is_expired() const noexcept
    {
        return elapsed() >= timeout_;
    }
};
} // namespace ws_client
