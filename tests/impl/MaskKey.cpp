#include <gtest/gtest.h>

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
