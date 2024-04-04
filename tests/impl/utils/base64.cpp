#include <gtest/gtest.h>

#include "ws_client/utils/base64.hpp"

using namespace ws_client;


TEST(Base64, encode_empty_string)
{
    EXPECT_TRUE(ws_client::base64_encode("") == "");
}

TEST(Base64, single_character)
{
    EXPECT_TRUE(ws_client::base64_encode("A") == "QQ==");
}

TEST(Base64, encode_3_char_string)
{
    EXPECT_TRUE(ws_client::base64_encode("Man") == "TWFu");
}

TEST(Base64, encode_requires_padding)
{
    EXPECT_TRUE(ws_client::base64_encode("Ma") == "TWE=");
}

TEST(Base64, encode_longer_string)
{
    EXPECT_TRUE(ws_client::base64_encode("Base64 encoding in C++ is fun!") ==
            "QmFzZTY0IGVuY29kaW5nIGluIEMrKyBpcyBmdW4h");
}

TEST(Base64, encode_f)
{
    EXPECT_TRUE(ws_client::base64_encode("f") == "Zg==");
}

TEST(Base64, encode_fo)
{
    EXPECT_TRUE(ws_client::base64_encode("fo") == "Zm8=");
}

TEST(Base64, encode_foo)
{
    EXPECT_TRUE(ws_client::base64_encode("foo") == "Zm9v");
}

TEST(Base64, encode_foob)
{
    EXPECT_TRUE(ws_client::base64_encode("foob") == "Zm9vYg==");
}

TEST(Base64, encode_fooba)
{
    EXPECT_TRUE(ws_client::base64_encode("fooba") == "Zm9vYmE=");
}

TEST(Base64, encode_foobar)
{
    EXPECT_TRUE(ws_client::base64_encode("foobar") == "Zm9vYmFy");
}
