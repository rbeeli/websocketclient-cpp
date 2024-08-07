#pragma once

#include <ostream>
#include <string>
#include <string_view>
#include <expected>

#include "ws_client/close_code.hpp"

namespace ws_client
{
using std::expected;
using std::string;

enum class WSErrorCode : uint8_t
{
    connection_closed = 1,
    transport_error = 3,
    protocol_error = 4,
    url_error = 5,
    buffer_error = 6,
    uncategorized_error = 7,
    compression_error = 8,
    timeout_error = 9,
    logic_error = 10,
};

static constexpr std::string_view to_string(const WSErrorCode& error)
{
    switch (error)
    {
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
        default:
            return "unknown";
    }
}

struct WSError
{
    WSErrorCode code;
    string message;
    close_code close_with_code;

    WSError(WSErrorCode code, string&& message)
        : code(code), message(std::move(message)), close_with_code(close_code::not_set)
    {
    }

    WSError(WSErrorCode code, string&& message, close_code close_with_code)
        : code(code), message(std::move(message)), close_with_code(close_with_code)
    {
    }
};

// iostream operator for WSError
inline std::ostream& operator<<(std::ostream& os, const WSError& error)
{
    os << "WSError(" << static_cast<int>(error.code) << ", " << to_string(error.code) << ", "
       << error.message << ", " << to_string(error.close_with_code) << ")";
    return os;
}

#define WS_ERROR(CODE, MESSAGE, CLOSE_CODE)                                                        \
    std::unexpected(WSError(WSErrorCode::CODE, MESSAGE, CLOSE_CODE))

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
            return std::unexpected(tmp.error());                                                     \
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
} // namespace ws_client
