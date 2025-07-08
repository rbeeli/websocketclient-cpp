#pragma once

#include <cstdint>
#include <ostream>
#include <format>
#include <string>
#include <string_view>
#include <expected>
#include <source_location>
#include <system_error>

namespace ws_client
{
/**
 * Enum for WebSocket close frame status codes as defined in RFC 6455.
 */
enum class close_code : uint16_t
{
    not_set = 0,

    // 1000 indicates a normal closure
    normal_closure = 1000,

    // 1001 indicates that an endpoint is "going away"
    going_away = 1001,

    // 1002 indicates terminating connection due to a protocol error
    protocol_error = 1002,

    // 1003 indicates terminating connection due to unacceptable data type
    unacceptable_data_type = 1003,

    // 1007 indicates termination due to inconsistent data within a message
    invalid_frame_payload_data = 1007,

    // 1008 indicates termination due to policy violation
    policy_violation = 1008,

    // 1009 indicates termination due to message too big
    message_too_big = 1009,

    // 1010 indicates client termination due to missing server extensions
    missing_extension = 1010,

    // 1011 indicates server termination due to unexpected condition
    unexpected_condition = 1011

    // 3000 - 3999 are reserved for use by libraries, frameworks, and applications
    // 4000 - 4999 are reserved for private use
};

static bool is_valid_close_code(close_code code) noexcept
{
    return code == close_code::normal_closure || code == close_code::going_away ||
           code == close_code::protocol_error || code == close_code::unacceptable_data_type ||
           code == close_code::invalid_frame_payload_data || code == close_code::policy_violation ||
           code == close_code::message_too_big || code == close_code::missing_extension ||
           code == close_code::unexpected_condition ||
           (static_cast<uint16_t>(code) >= 3000 && static_cast<uint16_t>(code) <= 4999);
}

static constexpr std::string_view to_string(close_code code) noexcept
{
    switch (code)
    {
        case close_code::not_set:
            return "not_set";
        case close_code::normal_closure:
            return "normal_closure";
        case close_code::going_away:
            return "going_away";
        case close_code::protocol_error:
            return "protocol_error";
        case close_code::unacceptable_data_type:
            return "unacceptable_data_type";
        case close_code::invalid_frame_payload_data:
            return "invalid_frame_payload_data";
        case close_code::policy_violation:
            return "policy_violation";
        case close_code::message_too_big:
            return "message_too_big";
        case close_code::missing_extension:
            return "missing_extension";
        case close_code::unexpected_condition:
            return "unexpected_condition";
        default:
            return "unknown";
    }
}

/**
 * Error codes for this WebSocket client.
 */
enum class WSErrorCode : int16_t
{
    success = 0,
    connection_closed = 1,
    transport_error = 3,
    protocol_error = 4,
    url_error = 5,
    buffer_error = 6,
    uncategorized_error = 7,
    compression_error = 8,
    timeout_error = 9,
    logic_error = 10,
    operation_cancelled = 11
};

static constexpr std::string_view to_string(WSErrorCode error) noexcept
{
    switch (error)
    {
        case WSErrorCode::success:
            return "success";
        case WSErrorCode::connection_closed:
            return "connection_closed";
        case WSErrorCode::transport_error:
            return "transport_error";
        case WSErrorCode::protocol_error:
            return "protocol_error";
        case WSErrorCode::url_error:
            return "url_error";
        case WSErrorCode::buffer_error:
            return "buffer_error";
        case WSErrorCode::uncategorized_error:
            return "uncategorized_error";
        case WSErrorCode::compression_error:
            return "compression_error";
        case WSErrorCode::timeout_error:
            return "timeout_error";
        case WSErrorCode::logic_error:
            return "logic_error";
        case WSErrorCode::operation_cancelled:
            return "operation_cancelled";
        default:
            return "unknown";
    }
}

/**
 * Error category for WebSocket client errors
 * based on STL `std::error_category`.
 */
class WSErrorCategory : public std::error_category
{
public:
    const char* name() const noexcept override
    {
        return "WSErrorCategory";
    }

    std::string message(int ev) const override
    {
        return std::string(to_string(static_cast<WSErrorCode>(ev)));
    }
};

const WSErrorCategory error_category{};

inline std::error_code make_error_code(WSErrorCode e) noexcept
{
    return {static_cast<int>(e), error_category};
}

struct WSError
{
    WSErrorCode code;
    std::string message;
    close_code close_with_code;
    std::source_location location;

    WSError(
        WSErrorCode code,
        std::string message,
        close_code close_with_code = close_code::not_set,
        const std::source_location& loc = std::source_location::current()
    ) noexcept
        : code(code), message(std::move(message)), close_with_code(close_with_code), location(loc)
    {
    }

    inline std::error_code to_error_code() const noexcept
    {
        return make_error_code(code);
    }

    inline std::string error_code_message() const
    {
        return error_category.message(static_cast<int>(code));
    }

    inline std::string to_string() const
    {
        return std::format(
            "WSClientError {}: {} (close code {}) at {}:{}:{} in {}",
            ws_client::to_string(code),
            message,
            ws_client::to_string(close_with_code),
            location.file_name(),
            location.line(),
            location.column(),
            location.function_name()
        );
    }
};

// iostream operator for WSError
inline std::ostream& operator<<(std::ostream& os, const WSError& error)
{
    os << error.to_string();
    return os;
}
} // namespace ws_client

namespace std
{
// Specialization of std::formatter for ws_client::WSError
template <>
struct formatter<ws_client::WSError>
{
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ws_client::WSError& e, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{}", e.to_string());
    }
};

// Specialization of std::formatter for ws_client::WSErrorCode
template <>
struct formatter<ws_client::WSErrorCode>
{
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ws_client::WSErrorCode& code, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{}", ws_client::to_string(code));
    }
};

// Specialization of std::is_error_code_enum for ws_client::WSErrorCode
template <>
struct is_error_code_enum<ws_client::WSErrorCode> : true_type
{
};
} // namespace std

// --------------------------------------------------------
// Helper macros for error handling in the WebSocket client
// --------------------------------------------------------

#define WS_ERROR(CODE, MESSAGE, CLOSE_CODE)                                                        \
    std::unexpected(ws_client::WSError(ws_client::WSErrorCode::CODE, MESSAGE, CLOSE_CODE))

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately as `unexpected{Type}`.
 * Otherwise, `expected` is stored in VARIABLE.
 */
#define WS_TRY(VARIABLE, EXPRESSION)                                                               \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                      \
        return std::unexpected((VARIABLE).error());

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately.
 * Otherwise, `expected` is stored in VARIABLE.
 */
#define WS_TRY_RAW(VARIABLE, EXPRESSION)                                                           \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                      \
        return (VARIABLE).error();

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately as `unexpected{Type}`.
 * Otherwise, nothing is returned (`V = void`).
 */
#define WS_TRYV(EXPRESSION)                                                                        \
    {                                                                                              \
        auto&& tmp = (EXPRESSION);                                                                 \
        if (!tmp.has_value()) [[unlikely]]                                                         \
            return std::unexpected(tmp.error());                                                   \
    }

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately.
 * Otherwise, nothing is returned (`V = void`).
 */
#define WS_TRYV_RAW(EXPRESSION)                                                                    \
    {                                                                                              \
        auto&& tmp = (EXPRESSION);                                                                 \
        if (!tmp.has_value()) [[unlikely]]                                                         \
            return tmp.error();                                                                    \
    }
