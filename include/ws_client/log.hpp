#pragma once

#include <string>
#include <string_view>
#include <format>
#include <cstdint>
#include <cassert>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <source_location>
#include <mutex>
#include <atomic>
#include <array>

namespace ws_client
{
// 0 = disabled, 1 = error, 2 = warning, 3 = info, 4 = debug
enum class LogLevel : uint8_t
{
    N = 0, // Disabled
    E = 1, // Error
    W = 2, // Warning
    I = 3, // Info
    D = 4  // Debug
};

static constexpr LogLevel log_level_from_int(int level)
{
    assert((level >= 0 && level <= 4) && "log level out of bounds");
    return static_cast<LogLevel>(level);
}

static constexpr std::string_view to_string(LogLevel level)
{
    switch (level)
    {
        case LogLevel::I:
            return "I";
        case LogLevel::D:
            return "D";
        case LogLevel::E:
            return "E";
        case LogLevel::W:
            return "W";
        default:
            return "?";
    }
}

inline std::ostream& operator<<(std::ostream& os, LogLevel level)
{
    return os << to_string(level);
}

enum class LogTopic : uint8_t
{
    None = 0,
    DNS = 1,              // WS_CLIENT_LOG_DNS
    TCP = 2,              // WS_CLIENT_LOG_TCP
    SSL = 3,              // WS_CLIENT_LOG_SSL
    Handshake = 4,        // WS_CLIENT_LOG_HANDSHAKE
    Compression = 5,      // WS_CLIENT_LOG_COMPRESSION
    SendFrame = 6,        // WS_CLIENT_LOG_SEND_FRAME
    SendFramePayload = 7, // WS_CLIENT_LOG_SEND_FRAME_PAYLOAD
    RecvFrame = 8,        // WS_CLIENT_LOG_RECV_FRAME
    RecvFramePayload = 9, // WS_CLIENT_LOG_RECV_FRAME_PAYLOAD
    User = 255            // WS_CLIENT_LOG_USER
};

constexpr size_t WS_LOG_TOPICS_COUNT = 11;

static constexpr std::string_view to_string(LogTopic topic)
{
    switch (topic)
    {
        case LogTopic::None:
            return "None";
        case LogTopic::DNS:
            return "DNS";
        case LogTopic::TCP:
            return "TCP";
        case LogTopic::SSL:
            return "SSL";
        case LogTopic::Handshake:
            return "Handshake";
        case LogTopic::Compression:
            return "Compression";
        case LogTopic::SendFrame:
            return "SendFrame";
        case LogTopic::SendFramePayload:
            return "SendFramePayload";
        case LogTopic::RecvFrame:
            return "RecvFrame";
        case LogTopic::RecvFramePayload:
            return "RecvFramePayload";
        case LogTopic::User:
            return "User";
        default:
            return "unknown";
    }
}

inline std::ostream& operator<<(std::ostream& os, LogTopic topic)
{
    return os << to_string(topic);
}

inline constexpr const char* extract_log_file_name(const char* path) noexcept
{
    const char* last_separator = nullptr;
    for (const char* p = path; *p; ++p)
    {
        if (*p == '/' || *p == '\\')
            last_separator = p + 1;
    }
    if (last_separator)
        return last_separator;
    return path;
}

/**
 * Default console logger.
 * It supports logging by topics, and log levels per topic.
 * The log level can be configured per topic at runtime, the operations are thread-safe.
 */
class ConsoleLogger
{
private:
    std::mutex clog_mutex;
    std::array<std::atomic<LogLevel>, WS_LOG_TOPICS_COUNT> topic_levels;

    template <LogLevel level>
    static constexpr std::string_view level_to_color() noexcept
    {
        if constexpr (level == LogLevel::E)
            return "\033[1;91m";
        if constexpr (level == LogLevel::W)
            return "\033[0;93m";
        if constexpr (level == LogLevel::I)
            return "\033[0;37m";
        if constexpr (level == LogLevel::D)
            return "\033[0;30m";
        return "";
    }

public:
    ConsoleLogger() noexcept //
        : ConsoleLogger(LogLevel::D)
    {
    }

    ConsoleLogger(LogLevel min_level) noexcept
    {
        // Configure defaults for log topics.
        // Defaults can be overridden using compile-time defines.
        set_level(LogTopic::DNS, log_level_from_int(WS_CLIENT_LOG_DNS));
        set_level(LogTopic::TCP, log_level_from_int(WS_CLIENT_LOG_TCP));
        set_level(LogTopic::SSL, log_level_from_int(WS_CLIENT_LOG_SSL));
        set_level(LogTopic::Handshake, log_level_from_int(WS_CLIENT_LOG_HANDSHAKE));
        set_level(LogTopic::Compression, log_level_from_int(WS_CLIENT_LOG_COMPRESSION));
        set_level(LogTopic::SendFrame, log_level_from_int(WS_CLIENT_LOG_SEND_FRAME));
        set_level(LogTopic::SendFramePayload, log_level_from_int(WS_CLIENT_LOG_SEND_FRAME_PAYLOAD));
        set_level(LogTopic::RecvFrame, log_level_from_int(WS_CLIENT_LOG_RECV_FRAME));
        set_level(LogTopic::RecvFramePayload, log_level_from_int(WS_CLIENT_LOG_RECV_FRAME_PAYLOAD));
        set_level(LogTopic::User, log_level_from_int(WS_CLIENT_LOG_USER));

        // set minimum log level
        set_min_level(min_level);
    }

    // disable copy
    ConsoleLogger(const ConsoleLogger&) = delete;
    ConsoleLogger& operator=(const ConsoleLogger&) = delete;

    // // enable move
    // ConsoleLogger(ConsoleLogger&&) noexcept = default;
    // ConsoleLogger& operator=(ConsoleLogger&&) noexcept = default;
    // TODO move
    ConsoleLogger(ConsoleLogger&&) = delete;
    ConsoleLogger& operator=(ConsoleLogger&&) = delete;

    /**
     * Check if the logger is enabled for the given log level and topic.
     * This function is thread-safe.
     */
    template <LogLevel level, LogTopic topic>
    bool is_enabled() const noexcept
    {
        size_t topic_ix = static_cast<size_t>(topic);
        LogLevel topic_level = topic_levels[topic_ix].load(std::memory_order::relaxed);
        return static_cast<int>(level) <= static_cast<int>(topic_level);
    }

    /**
     * Sets the log level for a given topic.
     * This method is thread-safe.
     */
    void set_level(LogTopic topic, LogLevel level) noexcept
    {
        topic_levels[static_cast<size_t>(topic)].store(level, std::memory_order::relaxed);
    }

    /**
     * Set the minimum log level for all log topics.
     * This overrides the compile-time defines per topic
     * if the passed minimum log level is stricter.
     */
    void set_min_level(LogLevel min_level) noexcept
    {
        for (size_t i = 0; i < topic_levels.size(); ++i)
        {
            auto topic_level = topic_levels[i].load(std::memory_order::relaxed);
            if (static_cast<int>(topic_level) > static_cast<int>(min_level))
                topic_levels[i].store(min_level, std::memory_order::relaxed);
        }
    }

    /**
     * Log a message with the given log level and topic.
     */
    template <LogLevel level, LogTopic topic>
    void log(
        std::string_view message, const std::source_location loc = std::source_location::current()
    ) noexcept
    {
        if (!is_enabled<level, topic>())
            return;

        // time of day
        auto now = std::chrono::system_clock::now();
        auto now_us = std::chrono::floor<std::chrono::microseconds>(now);

        // get color for log level
        constexpr auto color = level_to_color<level>();

        std::ostringstream msg;

        // write time
        msg << color << std::format("{:%Y-%m-%d %H:%M:%S}", now_us);

        // write log level
        msg << ' ' << level;

        // write log topic
        msg << ' ' << std::left << std::setw(17) << topic;

        // write file name and line number
        std::string filename_loc = std::format(
            "{}:{}", extract_log_file_name(loc.file_name()), loc.line()
        );
        msg << ' ' << std::left << std::setw(20) << filename_loc;

        // write message
        msg << ": " << color << message << "\x1b[0m" << '\n';

        {
            // synchronize clog output
            std::lock_guard<std::mutex> lock(clog_mutex);
            std::clog << msg.str() << std::flush;
        }
    }
};
} // namespace ws_client
