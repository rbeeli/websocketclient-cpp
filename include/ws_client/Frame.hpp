#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <span>
#include <limits>
#include <array>

#if WS_CLIENT_VALIDATE_UTF8 == 1
#include "ws_client/utils/utf8.hpp"
#endif

#include "ws_client/utils/networking.hpp"
#include "ws_client/MaskKey.hpp"
#include "ws_client/close_code.hpp"

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
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    rsv3 = 0x3,
    rsv4 = 0x4,
    rsv5 = 0x5,
    rsv6 = 0x6,
    rsv7 = 0x7,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    control_rsvb = 0xB,
    control_rsvc = 0xC,
    control_rsvd = 0xD,
    control_rsve = 0xE,
    control_rsvf = 0xF,
    not_set = 0xFF, // Not offical, used by this library internally
};

static bool is_reserved(opcode v) noexcept
{
    return (v >= opcode::rsv3 && v <= opcode::rsv7) ||
           (v >= opcode::control_rsvb && v <= opcode::control_rsvf);
}

static constexpr string_view to_string(opcode v)
{
    switch (v)
    {
        case opcode::continuation:
            return "continuation";
        case opcode::text:
            return "text";
        case opcode::binary:
            return "binary";
        case opcode::rsv3:
            return "rsv3";
        case opcode::rsv4:
            return "rsv4";
        case opcode::rsv5:
            return "rsv5";
        case opcode::rsv6:
            return "rsv6";
        case opcode::rsv7:
            return "rsv7";
        case opcode::close:
            return "close";
        case opcode::ping:
            return "ping";
        case opcode::pong:
            return "pong";
        case opcode::control_rsvb:
            return "control_rsvb";
        case opcode::control_rsvc:
            return "control_rsvc";
        case opcode::control_rsvd:
            return "control_rsvd";
        case opcode::control_rsve:
            return "control_rsve";
        case opcode::control_rsvf:
            return "control_rsvf";
        default:
            return "unknown";
    }
}

/**
 * The frame header is stored in the very first two bytes of the frame.
 * It encodes the opcode, final bit, rsv bits, masking bit, and
 * payload length (excluding extended payload length).
 */
struct FrameHeader
{
    static byte constexpr mask_opcode = byte{0x0F};
    static byte constexpr mask_rsv1 = byte{0x40};
    static byte constexpr mask_rsv2 = byte{0x20};
    static byte constexpr mask_rsv3 = byte{0x10};
    static byte constexpr mask_rsv_all = mask_rsv1 | mask_rsv2 | mask_rsv3;
    static byte constexpr mask_final = byte{0x80};
    static byte constexpr mask_payload = byte{0x7F};
    static byte constexpr mask_is_masked = byte{0x80};

    byte b0{0};
    byte b1{0};

    explicit FrameHeader() noexcept = default;

    explicit FrameHeader(byte b0, byte b1) noexcept : b0(b0), b1(b1)
    {
    }

    inline opcode op_code() const noexcept
    {
        return ws_client::opcode(this->b0 & mask_opcode);
    }

    inline bool is_final() const noexcept
    {
        return (this->b0 & mask_final) == mask_final;
    }

    inline bool is_control() const noexcept
    {
        return static_cast<uint8_t>(this->op_code()) >= 0x8;
    }

    inline bool has_rsv_bits() const noexcept
    {
        return (this->b0 & mask_rsv_all) != byte{0};
    }

    inline bool rsv1_bit() const noexcept
    {
        return (this->b0 & mask_rsv1) == mask_rsv1;
    }

    inline bool rsv1_bit_only() const noexcept
    {
        return (this->b0 & mask_rsv1) == mask_rsv1 && (this->b0 & mask_rsv2) == byte{0} &&
               (this->b0 & mask_rsv3) == byte{0};
    }

    inline bool rsv2_bit() const noexcept
    {
        return (this->b0 & mask_rsv2) == mask_rsv2;
    }

    inline bool rsv3_bit() const noexcept
    {
        return (this->b0 & mask_rsv3) == mask_rsv3;
    }

    inline bool is_masked() const noexcept
    {
        return (this->b1 & mask_is_masked) == mask_is_masked;
    }

    inline uint64_t get_basic_size() const noexcept
    {
        return static_cast<uint64_t>(this->b1 & mask_payload);
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
        this->header.b0 = (this->header.b0 & ~FrameHeader::mask_opcode) |
                          (static_cast<byte>(op) & FrameHeader::mask_opcode);
    }

    inline void set_is_final(bool value) noexcept
    {
        this->header.b0 = (this->header.b0 & ~FrameHeader::mask_final) |
                          (value ? FrameHeader::mask_final : byte{0});
    }

    inline void set_is_masked(bool value) noexcept
    {
        this->header.b1 = (this->header.b1 & ~FrameHeader::mask_is_masked) |
                          (value ? FrameHeader::mask_is_masked : byte{0});
    }

    inline void set_is_compressed(bool value) noexcept
    {
        this->header.b0 = (this->header.b0 & ~FrameHeader::mask_rsv1) |
                          (value ? FrameHeader::mask_rsv1 : byte{0});
    }

    inline void set_payload_size(size_t size) noexcept
    {
        this->payload_size = size;

        if (size <= 125)
        {
            // 7 bit payload length
            this->header.b1 = (this->header.b1 & ~FrameHeader::mask_payload) |
                              (static_cast<byte>(size) & FrameHeader::mask_payload);
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

struct ControlFrame
{
    opcode op_code;
    size_t payload_size{0};
    std::array<byte, 125> payload; // static allocation of payload bytes (max. 125 bytes)

    ControlFrame(opcode op, size_t payload_size) noexcept //
        : op_code(op), payload_size(payload_size)
    {
    }

    inline span<byte> payload_bytes() noexcept
    {
        return span<byte>(this->payload.data(), this->payload_size);
    }
};

struct CloseFrame final : public ControlFrame
{
    CloseFrame(size_t payload_size) noexcept //
        : ControlFrame(opcode::close, payload_size)
    {
    }

    inline bool has_close_code() const noexcept
    {
        return this->payload_size >= 2;
    }

    inline bool has_reason() const noexcept
    {
        return this->payload_size > 2;
    }

    inline close_code get_close_code() const noexcept
    {
        if (!this->has_close_code())
            return close_code::not_set;

        uint16_t ncode;
        std::memcpy(&ncode, payload.data(), sizeof(uint16_t));
        uint16_t code = network_to_host(ncode);
        return static_cast<close_code>(code);
    }

    inline string_view get_reason() const noexcept
    {
        if (!this->has_reason())
            return "";

        return string_view(
            reinterpret_cast<const char*>(this->payload.data() + 2), this->payload_size - 2
        );
    }

#if WS_CLIENT_VALIDATE_UTF8 == 1
    inline bool is_reason_valid_utf8() const noexcept
    {
        if (!this->has_reason())
            return true;

        auto reason_string = get_reason();
        return is_valid_utf8(reason_string.data(), reason_string.size());
    }
#endif
};

struct PingFrame final : public ControlFrame
{
    PingFrame(size_t payload_size) noexcept : ControlFrame(opcode::ping, payload_size)
    {
    }
};

struct PongFrame final : public ControlFrame
{
    PongFrame(size_t payload_size) noexcept : ControlFrame(opcode::pong, payload_size)
    {
    }
};

} // namespace ws_client
