#include <gtest/gtest.h>

#include <string>
#include <iostream>

#include "ws_client/config.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;

using std::string;
using std::span;
using std::byte;

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
    EXPECT_EQ(compressed.size(), 6);
    EXPECT_EQ(compressed[0], byte{0x02});
    EXPECT_EQ(compressed[1], byte{0x00});
    EXPECT_EQ(compressed[2], byte{0x00});
    EXPECT_EQ(compressed[3], byte{0x00});
    EXPECT_EQ(compressed[4], byte{0xFF});
    EXPECT_EQ(compressed[5], byte{0xFF});
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

    uint8_t buf[] = {0x02, 0x00, 0x00, 0x00, 0xff, 0xff};
    span<byte> payload{reinterpret_cast<byte*>(buf), 6};
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
    uint8_t buf[11] = {
        0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}; // trailer bytes stripped: 0x00, 0x00, 0xff, 0xff
    span<byte> payload{reinterpret_cast<byte*>(buf), 6};
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