#include <gtest/gtest.h>

#include <array>
#include <string>
#include <expected>
#include <iostream>
#include <random>
#include <string_view>
#include <utility>

#include "ws_client/config.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;

using std::string;
using std::span;
using std::byte;

TEST(PermessageDeflate, validates_window_bits)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> permessage_deflate{.logger = &logger};

    constexpr std::array<std::string_view, 7> invalid_values{
        "",
        "7",
        "16",
        "8junk",
        "15 ",
        "-248",
        "264",
    };
    for (const auto value : invalid_values)
        EXPECT_FALSE(permessage_deflate.parse_window_bits(std::string(value)).has_value()) << value;

    EXPECT_EQ(permessage_deflate.parse_window_bits("8"), 8);
    EXPECT_EQ(permessage_deflate.parse_window_bits("15"), 15);
}

/**
 * Permessage-deflate extension, as defined in RFC 7692.
 * 
 * https://datatracker.ietf.org/doc/rfc7692/
 */
TEST(PermessageDeflateContext, init)
{
    ConsoleLogger logger{LogLevel::D};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    EXPECT_TRUE(ctx.init().has_value());
}

TEST(PermessageDeflateContext, compress_empty)
{
    ConsoleLogger logger{LogLevel::D};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    EXPECT_TRUE(ctx.init().has_value());

    span<byte> payload{};
    auto res2 = ctx.compress(payload);
    EXPECT_TRUE(res2.has_value());
    span<byte> compressed = *res2;
    ASSERT_EQ(compressed.size(), 1);
    EXPECT_EQ(compressed[0], byte{0x00});
}

TEST(PermessageDeflateContext, decompress_empty)
{
    ConsoleLogger logger{LogLevel::D};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    EXPECT_TRUE(ctx.init().has_value());

    uint8_t buf[] = {0x00};
    span<byte> payload{reinterpret_cast<byte*>(buf), sizeof(buf)};
    ctx.decompress_buffer().append(payload.data(), payload.size());
    
    Buffer output = Buffer::create(0, 1024).value();

    auto res2 = ctx.decompress(output);
    EXPECT_TRUE(res2.has_value());
    EXPECT_EQ(output.size(), *res2);
    span<byte> decompressed = output.data();
    EXPECT_EQ(decompressed.size(), 0);
}

TEST(PermessageDeflateContext, decompress_hello)
{
    ConsoleLogger logger{LogLevel::D};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    EXPECT_TRUE(ctx.init().has_value());

    // Hello
    uint8_t buf[] = {
        0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00
    }; // trailer bytes stripped: 0x00, 0x00, 0xff, 0xff
    span<byte> payload{reinterpret_cast<byte*>(buf), sizeof(buf)};
    ctx.decompress_buffer().append(payload.data(), payload.size());

    Buffer output = Buffer::create(0, 1024).value();

    auto res2 = ctx.decompress(output);
    EXPECT_TRUE(res2.has_value());
    EXPECT_EQ(output.size(), *res2);
    span<byte> decompressed = output.data();
    string decompressed_str{reinterpret_cast<char*>(decompressed.data()), decompressed.size()};
    EXPECT_EQ(decompressed_str, "Hello");
}

TEST(PermessageDeflateContext, compress_decompress_loop)
{
    ConsoleLogger logger{LogLevel::D};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    EXPECT_TRUE(ctx.init().has_value());

    uint8_t buf[] = {0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00};
    string str = "Hello";
    span<byte> payload{reinterpret_cast<byte*>(str.data()), str.size()};
    ctx.decompress_buffer().append(payload.data(), payload.size());

    auto res2 = ctx.compress(payload);
    EXPECT_TRUE(res2.has_value());
    span<byte> compressed = *res2;
    EXPECT_EQ(compressed.size(), sizeof(buf));

    for (int i = 0; i < 100; i++)
    {
        ctx.decompress_buffer().clear();
        ctx.decompress_buffer().append(compressed.data(), compressed.size());

        Buffer output2 = Buffer::create(0, 1024).value();
        auto res2 = ctx.decompress(output2);
        EXPECT_TRUE(res2.has_value());
        span<byte> decompressed = output2.data();
        string decompressed_str{reinterpret_cast<char*>(decompressed.data()),
                                decompressed.size()};
        EXPECT_EQ(decompressed_str, "Hello");
    }
}

TEST(PermessageDeflateContext, preserves_context_takeover_between_messages)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = false,
        .client_no_context_takeover = false,
        .decompress_buffer_size = 1024 * 1024,
        .compress_buffer_size = 1024 * 1024,
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    ASSERT_TRUE(ctx.init().has_value());

    // RFC 7692 section 7.2.3.2: the second "Hello" references the first message's history.
    constexpr std::array first{
        byte{0xf2}, byte{0x48}, byte{0xcd}, byte{0xc9}, byte{0xc9}, byte{0x07}, byte{0x00}
    };
    constexpr std::array second{byte{0xf2}, byte{0x00}, byte{0x11}, byte{0x00}, byte{0x00}};
    const std::array messages{std::span<const byte>{first}, std::span<const byte>{second}};

    for (const auto compressed : messages)
    {
        ctx.decompress_buffer().clear();
        auto append_res = ctx.decompress_buffer().append(compressed.data(), compressed.size());
        ASSERT_TRUE(append_res.has_value());

        auto output_res = Buffer::create(0, 1024 * 1024);
        ASSERT_TRUE(output_res.has_value());

        Buffer output = std::move(*output_res);
        auto decompressed_res = ctx.decompress(output);
        ASSERT_TRUE(decompressed_res.has_value());

        string decompressed{reinterpret_cast<char*>(output.data().data()), output.size()};
        EXPECT_EQ(decompressed, "Hello");
    }
}

TEST(PermessageDeflateContext, decompress_after_bfinal_message_with_context_takeover)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = false,
        .client_no_context_takeover = false,
        .decompress_buffer_size = 1024 * 1024,
        .compress_buffer_size = 1024 * 1024,
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    ASSERT_TRUE(ctx.init().has_value());

    // RFC 7692 section 7.2.3.4: "Hello" in a BFINAL block, followed by a message
    // referencing the first message's history in the LZ77 sliding window.
    constexpr std::array<uint8_t, 8> first{0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00};
    constexpr std::array<uint8_t, 5> second{0xf2, 0x00, 0x11, 0x00, 0x00};
    const std::array<span<const byte>, 2> messages{as_bytes(span{first}), as_bytes(span{second})};

    for (const auto compressed : messages)
    {
        ctx.decompress_buffer().clear();
        ASSERT_TRUE(ctx.decompress_buffer().append(compressed.data(), compressed.size()));

        Buffer output = Buffer::create(0, 1024).value();
        auto decompressed_res = ctx.decompress(output);
        ASSERT_TRUE(decompressed_res.has_value());

        string decompressed{reinterpret_cast<char*>(output.data().data()), output.size()};
        EXPECT_EQ(decompressed, "Hello");
    }
}

TEST(PermessageDeflateContext, compress_empty_message_with_context_takeover)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = false,
        .client_no_context_takeover = false,
        .decompress_buffer_size = 1024 * 1024,
        .compress_buffer_size = 1024 * 1024,
    };

    PermessageDeflateContext<decltype(logger)> ctx{&logger, pd};
    ASSERT_TRUE(ctx.init().has_value());

    // loopback (same window bits for both directions): an empty message between
    // two messages must not break the decompressing peer
    for (const std::string_view msg : {"Hello", "", "", "Hello"})
    {
        ctx.compress_buffer().clear();
        string input{msg};
        span<byte> payload{reinterpret_cast<byte*>(input.data()), input.size()};
        auto compressed_res = ctx.compress(payload);
        ASSERT_TRUE(compressed_res.has_value());
        EXPECT_FALSE(compressed_res->empty());

        ctx.decompress_buffer().clear();
        ASSERT_TRUE(ctx.decompress_buffer().append(compressed_res->data(), compressed_res->size()));

        Buffer output = Buffer::create(0, 1024).value();
        ASSERT_TRUE(ctx.decompress(output).has_value());
        EXPECT_EQ(string(reinterpret_cast<char*>(output.data().data()), output.size()), msg);
    }
}

namespace
{
using DeflateContext = PermessageDeflateContext<ConsoleLogger>;

/**
 * Compresses `input` with `ctx` and decompresses it again (loopback) into a new buffer
 * with maximum size `output_max_size`.
 */
std::expected<string, WSError> compress_decompress(
    DeflateContext& ctx, string input, size_t output_max_size
)
{
    ctx.compress_buffer().clear();
    span<byte> payload{reinterpret_cast<byte*>(input.data()), input.size()};
    WS_TRY(compressed, ctx.compress(payload));

    ctx.decompress_buffer().clear();
    WS_TRYV(ctx.decompress_buffer().append(compressed->data(), compressed->size()));

    WS_TRY(output, Buffer::create(0, output_max_size));
    WS_TRYV(ctx.decompress(*output));
    return string(reinterpret_cast<char*>(output->data().data()), output->size());
}

string incompressible_data(size_t size)
{
    std::mt19937 rng(42);
    string data(size, '\0');
    for (auto& c : data)
        c = static_cast<char>(rng());
    return data;
}
} // namespace

TEST(PermessageDeflateContext, compress_message_larger_than_compress_buffer_size)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> pd{.logger = &logger}; // 100 KiB buffer limits
    DeflateContext ctx{&logger, pd};
    ASSERT_TRUE(ctx.init().has_value());

    // compresses well below the compress buffer limit
    const string input(200 * 1024, 'a');
    auto res = compress_decompress(ctx, input, 1024 * 1024);
    ASSERT_TRUE(res.has_value()) << res.error().message;
    EXPECT_EQ(*res, input);
}

TEST(PermessageDeflateContext, decompress_incompressible_message_up_to_max_size)
{
    ConsoleLogger logger{LogLevel::N};
    PermessageDeflate<decltype(logger)> pd{
        .logger = &logger,
        .decompress_buffer_size = 1024 * 1024,
        .compress_buffer_size = 1024 * 1024,
    };
    const string input = incompressible_data(100 * 1024);

    {
        DeflateContext ctx{&logger, pd};
        ASSERT_TRUE(ctx.init().has_value());
        auto res = compress_decompress(ctx, input, input.size() + 1);
        ASSERT_TRUE(res.has_value()) << res.error().message;
        EXPECT_EQ(*res, input);
    }

    {
        DeflateContext ctx{&logger, pd};
        ASSERT_TRUE(ctx.init().has_value());
        auto res = compress_decompress(ctx, input, input.size() - 1);
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, WSErrorCode::buffer_error);
    }
}
