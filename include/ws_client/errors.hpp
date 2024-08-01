#pragma once

#include <ostream>
#include <string>
#include <expected>

#include "ws_client/close_code.hpp"

namespace ws_client
{
using std::expected;
using std::unexpected;
using std::string;
using std::string_view;

enum class WSErrorCode : uint8_t
{
    connection_closed = 1,
    transport_error = 3,
    protocol_error = 4,
    url_error = 5,
    buffer_error = 6,
    uncategorized = 7,
    compression_error = 8,
    timeout = 9,
    logic_error = 10,
};

static constexpr string_view to_string(const WSErrorCode& error)
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
        case WSErrorCode::uncategorized:
            return "uncategorized";
        case WSErrorCode::compression_error:
            return "compression_error";
        case WSErrorCode::timeout:
            return "timeout";
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

    WSError(WSErrorCode code, string message)
        : code(code), message(message), close_with_code(close_code::not_set)
    {
    }

    WSError(WSErrorCode code, string message, close_code close_with_code)
        : code(code), message(message), close_with_code(close_with_code)
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

#define WS_UNEXPECTED(EXPRESSION) unexpected(EXPRESSION)

#define WS_ERROR(CODE, MESSAGE, CLOSE_CODE)                                                        \
    WS_UNEXPECTED(WSError(WSErrorCode::CODE, MESSAGE, close_code::CLOSE_CODE))

#define WS_ERROR_RAW(CODE, MESSAGE, CLOSE_CODE)                                                    \
    WSError(WSErrorCode::CODE, MESSAGE, close_code::CLOSE_CODE)

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately as `unexpected{Type}`.
 * Otherwise, `expected` is stored in VARIABLE.
 */
#define WS_TRY(VARIABLE, EXPRESSION)                                                               \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                      \
        return WS_UNEXPECTED((VARIABLE).error());

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
            return WS_UNEXPECTED(tmp.error());                                                     \
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
