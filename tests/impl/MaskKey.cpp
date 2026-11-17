#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <iostream>

#include "ws_client/MaskKey.hpp"

using namespace ws_client;

using std::string;
using std::span;
using std::byte;

constexpr uint32_t mask_key = uint32_t(35636262393);

TEST(MaskKey, empty_string)
{
    string payload_str = "";
    span payload(reinterpret_cast<byte*>(payload_str.data()), payload_str.size());
    MaskKey key(mask_key);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == payload_str);
}

TEST(MaskKey, _1_character)
{
    string payload_str = "a";
    span payload(reinterpret_cast<byte*>(payload_str.data()), payload_str.size());
    MaskKey key(mask_key);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == payload_str);
}

TEST(MaskKey, _7_character)
{
    string payload_str = "abcdefg";
    span payload(reinterpret_cast<byte*>(payload_str.data()), payload_str.size());
    MaskKey key(mask_key);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == payload_str);
}

TEST(MaskKey, _8_character)
{
    string payload_str = "abcdefgh";
    span payload(reinterpret_cast<byte*>(payload_str.data()), payload_str.size());
    MaskKey key(mask_key);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == payload_str);
}

TEST(MaskKey, ping_payload)
{
    string payload_str = "ping payload";
    span payload(reinterpret_cast<byte*>(payload_str.data()), payload_str.size());
    MaskKey key(mask_key);

    EXPECT_TRUE(payload_str == "ping payload");
    key.mask(payload);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == payload_str);
}

TEST(MaskKey, mask_key_unaligned)
{
    string payload_str = R"(   {"method":"subscribe","subscription":{"type":"user"})";
    span payload(reinterpret_cast<byte*>(payload_str.data()+3), payload_str.size()-3);
    MaskKey key(mask_key);

    key.mask(payload);
    key.mask(payload);
    EXPECT_TRUE(string((char*)payload.data(), payload.size()) == R"({"method":"subscribe","subscription":{"type":"user"})");
}

TEST(MaskKey, matches_reference_for_all_offsets)
{
    alignas(64) byte data[256];
    alignas(64) byte expected[256];

    const uint32_t key = 0xa5c3f00f;
    byte key_bytes[4];
    std::memcpy(key_bytes, &key, sizeof(key));

    for (size_t offset = 0; offset < 32; ++offset)
    {
        for (size_t size = 0; size <= 200; ++size)
        {
            for (size_t i = 0; i < size; ++i)
            {
                const byte value = static_cast<byte>((i * 31 + offset) & 0xff);
                data[offset + i] = value;
                expected[offset + i] = value ^ key_bytes[i & 3];
            }

            MaskKey(key).mask(span(data + offset, size));

            ASSERT_EQ(std::memcmp(data + offset, expected + offset, size), 0)
                << "offset = " << offset << ", size = " << size;
        }
    }
}
