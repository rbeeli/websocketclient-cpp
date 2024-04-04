#pragma once

#include <string_view>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <source_location>

namespace ws_client
{
using std::string_view;

// 0 = disabled, 1 = error, 2 = warning, 3 = info, 4 = debug
enum class LogLevel : uint8_t
{
    N = 0, // Disabled
    E = 1, // Error
    W = 2, // Warning
    I = 3, // Info
    D = 4  // Debug
};

inline std::ostream& operator<<(std::ostream& os, LogLevel level)
{
    static const char buffer[] = {' ', 'E', 'W', 'I', 'D'};
    return os << buffer[static_cast<int>(level)];
}

template <LogLevel min_level>
class ConsoleLogger
{
private:
    static constexpr const char* extract_file_name(const char* path)
    {
        const char* last_slash = nullptr;
        for (const char* p = path; *p; ++p)
        {
            if (*p == '/')
                last_slash = p + 1;
        }
        if (last_slash)
            return last_slash;
        return path;
    }

    static constexpr char* extract_function_name(
        const char* func_full_name, char* func_name, const long max_width, const long buf_size
    )
    {
        const char* last_colon = nullptr;
        const char* func_start = nullptr;
        const char* func_end = nullptr;
        for (const char* p = func_full_name; *p; ++p)
        {
            if (*p == ':' && *(p + 1) == ':')
                last_colon = p + 2; // skip the "::"
            if (*p == '(' && last_colon)
            {
                func_end = p;
                break;
            }
        }
        if (last_colon && func_end)
            func_start = last_colon;
        if (func_start && func_end)
        {
            long length = func_end - func_start;
            if (length > 0 && length < buf_size)
            {
                bool truncated = length > max_width;
                if (truncated)
                    length = max_width;
                for (long i = 0; i < length; ++i)
                    func_name[i] = func_start[i];
                if (truncated)
                    func_name[length - 1] = '.';
                func_name[length] = '\0';
                return func_name;
            }
        }
        return nullptr;
    }

    template <LogLevel level>
    static constexpr std::string_view level_to_color()
    {
        if constexpr (level == LogLevel::E)
            return "\033[1;91m";
        else if constexpr (level == LogLevel::W)
            return "\033[0;93m";
        else if constexpr (level == LogLevel::I)
            return "\033[0;37m";
        else if constexpr (level == LogLevel::D)
            return "\033[0;30m";
        else
            return "";
    }

public:
    ConsoleLogger() noexcept = default;

    // disable copy
    ConsoleLogger(const ConsoleLogger&) = delete;
    ConsoleLogger& operator=(const ConsoleLogger&) = delete;

    // enable move
    ConsoleLogger(ConsoleLogger&&) noexcept = default;
    ConsoleLogger& operator=(ConsoleLogger&&) noexcept = default;

    /**
     * Check if the logger is enabled for the given log level.
     */
    template <LogLevel level>
    constexpr bool is_enabled() const noexcept
    {
        return static_cast<int>(level) <= static_cast<int>(min_level);
    }

    /**
     * Log a message with the given log level.
     */
    template <LogLevel level>
    constexpr void log(
        string_view message, const std::source_location loc = std::source_location::current()
    ) noexcept
    {
        if (!is_enabled<level>())
            return;

        // time of day
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) %
                  std::chrono::seconds(1);

        static thread_local std::ostringstream msg;

        // extract function name / line number
        char func_name[256];
        constexpr int func_len = 20;
        std::string filename_loc = extract_file_name(loc.file_name());
        filename_loc.append(":");
        filename_loc.append(std::to_string(loc.line()));

        constexpr auto color = level_to_color<level>();

        // write time
        msg << color << std::put_time(std::localtime(&now_t), "%T") << '.' << std::setfill('0')
            << std::setw(6) << us.count() << std::setfill(' ');

        // write log level
        msg << ' ' << level << ' ';

        // write location
        msg << std::left << std::setw(20) << filename_loc //
            << ":\033[1m" << std::left << std::setw(func_len)
            << extract_function_name(loc.function_name(), func_name, func_len, 256) //
            << color << " ";

        // write message
        msg << message << "\x1b[0m" << '\n';

        std::clog << msg.str();
        std::flush(std::clog);

        msg.str(""); // clear stream for reuse
    }
};

} // namespace ws_client
