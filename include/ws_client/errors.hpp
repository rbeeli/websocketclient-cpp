#pragma once

#include <ostream>
#include <string>
#include <expected>

namespace ws_client
{
using std::expected;
using std::unexpected;
using std::string;
using std::string_view;

enum class WSErrorCode : uint8_t
{
    CONNECTION_CLOSED = 1,
    CONNECTION_CLOSED_BY_PEER = 2,
    TRANSPORT_ERROR = 3,
    PROTOCOL_ERROR = 4,
    URL_ERROR = 5,
    BUFFER_ERROR = 6,
    UNCATEGORIZED = 7,
    COMPRESSION_ERROR = 8,
    TIMEOUT = 9,
};

static constexpr string_view to_string(const WSErrorCode& error)
{
    switch (error)
    {
        case WSErrorCode::CONNECTION_CLOSED:
            return "CONNECTION_CLOSED";
        case WSErrorCode::CONNECTION_CLOSED_BY_PEER:
            return "CONNECTION_CLOSED_BY_PEER";
        case WSErrorCode::TRANSPORT_ERROR:
            return "TRANSPORT_ERROR";
        case WSErrorCode::PROTOCOL_ERROR:
            return "PROTOCOL_ERROR";
        case WSErrorCode::URL_ERROR:
            return "URL_ERROR";
        case WSErrorCode::BUFFER_ERROR:
            return "BUFFER_ERROR";
        case WSErrorCode::UNCATEGORIZED:
            return "UNCATEGORIZED";
        case WSErrorCode::COMPRESSION_ERROR:
            return "COMPRESSION_ERROR";
        case WSErrorCode::TIMEOUT:
            return "TIMEOUT";
        default:
            return "UNKNOWN_ERROR";
    }
}

struct WSError
{
    WSErrorCode code;
    string message;

    WSError(WSErrorCode code_, string message_) : code(code_), message(message_)
    {
    }
};

// iostream operator for WSError
inline std::ostream& operator<<(std::ostream& os, const WSError& error)
{
    os << "WSError(" << static_cast<int>(error.code) << ", " << to_string(error.code) << ", "
       << error.message << ")";
    return os;
}

#define WS_UNEXPECTED(EXPRESSION) unexpected(EXPRESSION)

#define WS_ERROR(CODE, MESSAGE) WS_UNEXPECTED(WSError(WSErrorCode::CODE, MESSAGE))

/**
 * Checks if the expression returns an `expected` with an error.
 * If so, the error is returned up the stack immediately.
 * Otherwise, `expected` is stored in VARIABLE.
 */
#define WS_TRY(VARIABLE, EXPRESSION)                                                               \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                    \
        return WS_UNEXPECTED((VARIABLE).error());

/**
 * Checks if the expression returns a `expected` with an error.
 * If so, the error is returned up the stack immediately.
 * Otherwise, nothing is returned (`V = void`).
 */
#define WS_TRYV(EXPRESSION)                                                                        \
    {                                                                                              \
        auto&& tmp = (EXPRESSION);                                                                 \
        if (!tmp.has_value()) [[unlikely]]                                                      \
            return WS_UNEXPECTED(tmp.error());                                                     \
    }

} // namespace ws_client
