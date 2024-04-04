#pragma once

#include <string>
#include <cstdint>
#include <span>
#include <limits>

#include "ws_client/MaskKey.hpp"

// Framing protocol for websockets
// https://datatracker.ietf.org/doc/html/rfc6455
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

namespace ws_client
{
using std::string;
using std::string_view;
using std::byte;
using std::span;

/**
 * Frame opcodes are 4 bits, see RFC 6455, Section "5.2. Base Framing Protocol".
 */
enum class opcode : uint8_t
{
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    RSV3 = 0x3,
    RSV4 = 0x4,
    RSV5 = 0x5,
    RSV6 = 0x6,
    RSV7 = 0x7,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
    CONTROL_RSVB = 0xB,
    CONTROL_RSVC = 0xC,
    CONTROL_RSVD = 0xD,
    CONTROL_RSVE = 0xE,
    CONTROL_RSVF = 0xF,
    NOT_SET = 0xFF, // Not offical, used by this library internally
};

static bool is_reserved(opcode v) noexcept
{
    return (v >= opcode::RSV3 && v <= opcode::RSV7) ||
           (v >= opcode::CONTROL_RSVB && v <= opcode::CONTROL_RSVF);
}

static constexpr string to_string(opcode v)
{
    switch (v)
    {
        case opcode::CONTINUATION:
            return "CONTINUATION";
        case opcode::TEXT:
            return "TEXT";
        case opcode::BINARY:
            return "BINARY";
        case opcode::RSV3:
            return "RSV3";
        case opcode::RSV4:
            return "RSV4";
        case opcode::RSV5:
            return "RSV5";
        case opcode::RSV6:
            return "RSV6";
        case opcode::RSV7:
            return "RSV7";
        case opcode::CLOSE:
            return "CLOSE";
        case opcode::PING:
            return "PING";
        case opcode::PONG:
            return "PONG";
        case opcode::CONTROL_RSVB:
            return "CONTROL_RSVB";
        case opcode::CONTROL_RSVC:
            return "CONTROL_RSVC";
        case opcode::CONTROL_RSVD:
            return "CONTROL_RSVD";
        case opcode::CONTROL_RSVE:
            return "CONTROL_RSVE";
        case opcode::CONTROL_RSVF:
            return "CONTROL_RSVF";
        default:
            return "UNKNOWN (" + std::to_string(static_cast<uint8_t>(v)) + ")";
    }
}

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


/**
 * WebSockets frame header is stored in the very
 * first two bytes of the frame.
 */
struct FrameHeader
{
    static byte constexpr MASK_OPCODE = byte{0x0F};
    static byte constexpr MASK_RSV_1 = byte{0x40};
    static byte constexpr MASK_RSV_2 = byte{0x20};
    static byte constexpr MASK_RSV_3 = byte{0x10};
    static byte constexpr MASK_RSV_ALL = MASK_RSV_1 | MASK_RSV_2 | MASK_RSV_3;
    static byte constexpr MASK_FINAL = byte{0x80};
    static byte constexpr MASK_PAYLOAD = byte{0x7F};
    static byte constexpr MASK_IS_MASKED = byte{0x80};

    byte b0{0};
    byte b1{0};

    explicit FrameHeader() noexcept = default;

    explicit FrameHeader(byte b0, byte b1) noexcept : b0(b0), b1(b1)
    {
    }

    inline opcode op_code() const noexcept
    {
        return ws_client::opcode(this->b0 & MASK_OPCODE);
    }

    inline bool is_final() const noexcept
    {
        return (this->b0 & MASK_FINAL) == MASK_FINAL;
    }

    inline bool is_control() const noexcept
    {
        return static_cast<uint8_t>(this->op_code()) >= 0x8;
    }

    inline bool has_rsv_bits() const noexcept
    {
        return (this->b0 & MASK_RSV_ALL) != byte{0};
    }

    inline bool rsv1_bit() const noexcept
    {
        return (this->b0 & MASK_RSV_1) == MASK_RSV_1;
    }

    inline bool rsv1_bit_only() const noexcept
    {
        return (this->b0 & MASK_RSV_1) == MASK_RSV_1 && (this->b0 & MASK_RSV_2) == byte{0} &&
               (this->b0 & MASK_RSV_3) == byte{0};
    }

    inline bool rsv2_bit() const noexcept
    {
        return (this->b0 & MASK_RSV_2) == MASK_RSV_2;
    }

    inline bool rsv3_bit() const noexcept
    {
        return (this->b0 & MASK_RSV_3) == MASK_RSV_3;
    }

    inline bool is_masked() const noexcept
    {
        return (this->b1 & MASK_IS_MASKED) == MASK_IS_MASKED;
    }

    inline uint64_t get_basic_size() const noexcept
    {
        return static_cast<uint64_t>(this->b1 & MASK_PAYLOAD);
    }
};

/**
 * WebSockets frame data structure.
 * The frame header is stored in the first two bytes.
 * The payload itself is not stored in this structure, instead
 * read and passed around separately.
 */
struct Frame
{
    // 2 bytes (uint16) frame header
    FrameHeader header{};

    // 4 bytes (uint32) masking (set by client for server only)
    MaskKey mask_key{};

    // size of payload in bytes
    size_t payload_size{0};

    inline void set_opcode(const opcode op) noexcept
    {
        this->header.b0 = (this->header.b0 & ~FrameHeader::MASK_OPCODE) |
                          (static_cast<byte>(op) & FrameHeader::MASK_OPCODE);
    }

    inline void set_is_final(bool value) noexcept
    {
        this->header.b0 = (this->header.b0 & ~FrameHeader::MASK_FINAL) |
                          (value ? FrameHeader::MASK_FINAL : byte{0});
    }

    inline void set_is_masked(bool value) noexcept
    {
        this->header.b1 = (this->header.b1 & ~FrameHeader::MASK_IS_MASKED) |
                          (value ? FrameHeader::MASK_IS_MASKED : byte{0});
    }

    inline void set_is_compressed(bool value) noexcept
    {
        this->header.b0 = (this->header.b0 & ~FrameHeader::MASK_RSV_1) |
                          (value ? FrameHeader::MASK_RSV_1 : byte{0});
    }

    inline void set_payload_size(size_t size) noexcept
    {
        this->payload_size = size;

        if (size <= 125)
        {
            // 7 bit payload length
            this->header.b1 = (this->header.b1 & ~FrameHeader::MASK_PAYLOAD) |
                              (static_cast<byte>(size) & FrameHeader::MASK_PAYLOAD);
        }
        else if (size <= UINT16_MAX)
        {
            // 16 bit payload length
            this->header.b1 |= byte{0x7E}; // 126
        }
        else [[unlikely]]
        {
            // full 64 bit payload length
            this->header.b1 |= byte{0x7F}; // 127
        }
    }

    Frame() noexcept = default;
    Frame(const Frame&) noexcept = default;
    Frame& operator=(const Frame&) noexcept = default;
    Frame(Frame&&) noexcept = default;
    Frame& operator=(Frame&&) noexcept = default;
    ~Frame() noexcept = default;
};

} // namespace ws_client
