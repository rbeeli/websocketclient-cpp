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

static bool is_valid_close_code(close_code code)
{
    return code == close_code::normal_closure || code == close_code::going_away ||
           code == close_code::protocol_error || code == close_code::unacceptable_data_type ||
           code == close_code::invalid_frame_payload_data || code == close_code::policy_violation ||
           code == close_code::message_too_big || code == close_code::missing_extension ||
           code == close_code::unexpected_condition ||
           (static_cast<uint16_t>(code) >= 3000 && static_cast<uint16_t>(code) <= 4999);
}

static constexpr string to_string(close_code code)
{
    switch (code)
    {
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
            return "Unknown (" + std::to_string(static_cast<uint16_t>(code)) + ")";
    }
}
}; // namespace ws_client