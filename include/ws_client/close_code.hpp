#pragma once

#include <cstdint>

namespace ws_client
{
using std::string;

/**
 * Enum for WebSocket close frame status codes as defined in RFC 6455.
 */
enum class close_code : uint16_t
{
    NOT_SET = 0,

    // 1000 indicates a normal closure
    NORMAL_CLOSURE = 1000,

    // 1001 indicates that an endpoint is "going away"
    GOING_AWAY = 1001,

    // 1002 indicates terminating connection due to a protocol error
    PROTOCOL_ERROR = 1002,

    // 1003 indicates terminating connection due to unacceptable data type
    UNACCEPTABLE_DATA_TYPE = 1003,

    // 1007 indicates termination due to inconsistent data within a message
    INVALID_FRAME_PAYLOAD_DATA = 1007,

    // 1008 indicates termination due to policy violation
    POLICY_VIOLATION = 1008,

    // 1009 indicates termination due to message too big
    MESSAGE_TOO_BIG = 1009,

    // 1010 indicates client termination due to missing server extensions
    MISSING_EXTENSION = 1010,

    // 1011 indicates server termination due to unexpected condition
    UNEXPECTED_CONDITION = 1011

    // 3000 - 3999 are reserved for use by libraries, frameworks, and applications
    // 4000 - 4999 are reserved for private use
};

static bool is_valid_close_code(close_code code)
{
    return code == close_code::NORMAL_CLOSURE || code == close_code::GOING_AWAY ||
           code == close_code::PROTOCOL_ERROR || code == close_code::UNACCEPTABLE_DATA_TYPE ||
           code == close_code::INVALID_FRAME_PAYLOAD_DATA || code == close_code::POLICY_VIOLATION ||
           code == close_code::MESSAGE_TOO_BIG || code == close_code::MISSING_EXTENSION ||
           code == close_code::UNEXPECTED_CONDITION ||
           (static_cast<uint16_t>(code) >= 3000 && static_cast<uint16_t>(code) <= 4999);
}

static constexpr string to_string(close_code code)
{
    switch (code)
    {
        case close_code::NORMAL_CLOSURE:
            return "NORMAL_CLOSURE";
        case close_code::GOING_AWAY:
            return "GOING_AWAY";
        case close_code::PROTOCOL_ERROR:
            return "PROTOCOL_ERROR";
        case close_code::UNACCEPTABLE_DATA_TYPE:
            return "UNACCEPTABLE_DATA_TYPE";
        case close_code::INVALID_FRAME_PAYLOAD_DATA:
            return "INVALID_FRAME_PAYLOAD_DATA";
        case close_code::POLICY_VIOLATION:
            return "POLICY_VIOLATION";
        case close_code::MESSAGE_TOO_BIG:
            return "MESSAGE_TOO_BIG";
        case close_code::MISSING_EXTENSION:
            return "MISSING_EXTENSION";
        case close_code::UNEXPECTED_CONDITION:
            return "UNEXPECTED_CONDITION";
        default:
            return "UNKNOWN (" + std::to_string(static_cast<uint16_t>(code)) + ")";
    }
}
}; // namespace ws_client