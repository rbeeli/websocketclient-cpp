#pragma once

#include <ostream>
#include <string>
#include <string_view>
#include <cstddef>
#include <span>

#include "ws_client/Frame.hpp"

namespace ws_client
{
using std::string;
using std::string_view;
using std::byte;
using std::span;

enum class MessageType : uint8_t
{
    text = static_cast<uint8_t>(opcode::text),
    binary = static_cast<uint8_t>(opcode::binary)
};

static constexpr string_view to_string(MessageType v)
{
    switch (v)
    {
        case MessageType::text:
            return "text";
        case MessageType::binary:
            return "binary";
        default:
            return "unknown";
    }
}

struct MessageReadState
{
    bool is_compressed = false;
    bool is_first = true;
    opcode op_code = opcode::not_set;

    void reset() noexcept
    {
        is_compressed = false;
        is_first = true;
        op_code = opcode::not_set;
    }
};

/**
 * Data container for Web Socket messages.
 * Buffer `data` may be modified in-place, but MUST NOT be deleted.
 * The buffer is owned by the caller of the constructor.
 * The buffer MUST remain valid for the lifetime of this `Message` instance.
 */
struct Message
{
    MessageType type;
    span<byte> data;

    /**
     * Creates a Message from a buffer, without copying the data.
     * The passed buffer MUST remain valid for the lifetime of this `Message` instance.
     */
    explicit Message(MessageType type, span<byte> data) noexcept //
        : type(type), data(data)
    {
    }

    /**
     * Creates a Message from a buffer, without copying the data.
     * The passed buffer MUST remain valid for the lifetime of this `Message` instance.
     */
    explicit Message(MessageType type, span<const byte> data) noexcept //
        : type(type), data(const_cast<byte*>(data.data()), data.size())
    {
    }

    /**
     * Creates a Message from a `string_view`, without copying the data.
     * The string underlying the passed `string_view` MUST remain valid
     * for the lifetime of this `Message` instance.
     */
    explicit Message(MessageType type, string_view data) noexcept
        : type(type),
          data(span<byte>(reinterpret_cast<byte*>(const_cast<char*>(data.data())), data.size()))
    {
    }

    /**
     * Returns a `string_view` of the message payload.
     * The returned `string_view` is valid as long as the underlying
     * `Message` buffer is valid.
     */
    [[nodiscard]] inline string_view to_string_view() const noexcept
    {
        return string_view(reinterpret_cast<const char*>(data.data()), data.size());
    }

    /**
     * Returns a `string` copy of the message payload.
     */
    [[nodiscard]] inline string to_string() const noexcept
    {
        return string(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

// iostream operator for Message
inline std::ostream& operator<<(std::ostream& os, const Message& msg)
{
    os << "Message(type=" << to_string(msg.type) << ", data=" << msg.to_string_view() << ")";
    return os;
}

struct SendOptions
{
    /**
     * Whether to compress the message payload.
     * Only applicable if permessage-deflate compression
     * was negotiated during the WebSocket handshake,
     * otherwise this option is ignored.
     *
     * Default: `true`
     */
    bool compress{true};

    /**
     * Timeout for sending the message, in milliseconds.
     * If the message cannot be sent within this time,
     * the send operation will fail with a timeout error.
     *
     * Default: 30 seconds.
     */
    std::chrono::milliseconds timeout{std::chrono::seconds(30)};
};

// iostream operator for SendOptions
inline std::ostream& operator<<(std::ostream& os, const SendOptions& opts)
{
    os << "SendOptions(compress=" << opts.compress << ")";
    return os;
}

} // namespace ws_client
