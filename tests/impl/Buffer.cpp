#include <gtest/gtest.h>

#include <string>
#include <span>
#include <iostream>

#include "ws_client/errors.hpp"
#include "ws_client/Buffer.hpp"

using namespace ws_client;
using std::span;
using std::string;


TEST(Buffer, DefaultConstruction)
{
    Buffer buf;
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.max_size(), Buffer::default_max_size);
}

TEST(Buffer, MoveConstruction)
{
    string data = "test";
    span<byte> data_span(reinterpret_cast<byte*>(data.data()), data.size());

    Buffer buf1(1024);
    auto res = buf1.append(data_span.data(), 4);
    ASSERT_TRUE(res.has_value());
    Buffer buf2(std::move(buf1));

    EXPECT_EQ(buf2.size(), 4);
    EXPECT_EQ(buf1.size(), 0); // Ensure buf1 is in a valid state after move
}

TEST(Buffer, MoveAssignment)
{
    Buffer buf1;
    auto res = buf1.append(4);
    ASSERT_TRUE(res.has_value());
    Buffer buf2;
    buf2 = std::move(buf1);

    EXPECT_EQ(buf2.size(), 4);
    EXPECT_EQ(buf1.size(), 0); // buf1 should be empty after move assignment
}

TEST(Buffer, AppendAndAccess)
{
    string data = "test";
    span<byte> data_span(reinterpret_cast<byte*>(data.data()), data.size());

    Buffer buf;
    auto res = buf.append(data_span.data(), 4);
    ASSERT_TRUE(res.has_value());

    EXPECT_EQ(buf.size(), data.size());
    EXPECT_EQ(std::memcmp(buf.data().data(), data_span.data(), data_span.size()), 0);
}

TEST(Buffer, AppendN)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(buf.size(), 4);
    EXPECT_TRUE(buf.data().data() != nullptr);
    EXPECT_FALSE(buf.data().empty());
    EXPECT_FALSE(buf.full());
}

TEST(Buffer, ResetAndAppendN)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(buf.size(), 4);
    EXPECT_TRUE(buf.data().data() != nullptr);
    EXPECT_FALSE(buf.data().empty());
    EXPECT_FALSE(buf.full());

    buf.reset();

    auto res2 = buf.append(4);
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(buf.size(), 4);
    EXPECT_TRUE(buf.data().data() != nullptr);
    EXPECT_FALSE(buf.data().empty());
    EXPECT_FALSE(buf.full());
}

TEST(Buffer, ReserveAndResize)
{
    Buffer buf;
    auto res = buf.reserve(1024);
    ASSERT_TRUE(res.has_value());
    EXPECT_LE(1024, buf.max_size() - buf.size());

    auto res2 = buf.resize(512);
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(buf.size(), 512);
}

TEST(Buffer, ExceedingMaxSize)
{
    Buffer buf;
    buf.set_max_size(10);
    auto res = buf.append(20);
    EXPECT_FALSE(res.has_value());
}

TEST(Buffer, ClearFunctionality)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(buf.size(), 4);

    buf.clear();
    EXPECT_EQ(buf.size(), 0);
    EXPECT_NE(buf.max_size() - buf.size(), 0); // Assuming capacity is not reduced
}

TEST(Buffer, EmptyMethod)
{
    Buffer buf;
    EXPECT_TRUE(buf.empty());

    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(buf.empty());

    buf.clear();
    EXPECT_TRUE(buf.empty());
}

TEST(Buffer, AtAndOperator)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    EXPECT_NO_THROW((void)buf.at(0));
    EXPECT_NO_THROW((void)buf[0]);
}

TEST(Buffer, SetAndGetMaxSize)
{
    Buffer buf;
    size_t newMaxSize = 32 * 1024; // 32 KB
    buf.set_max_size(newMaxSize);
    EXPECT_EQ(buf.max_size(), newMaxSize);

    auto res = buf.append(newMaxSize + 1);
    EXPECT_FALSE(res.has_value()); // Should not allow exceeding new max size
}

TEST(Buffer, ResizeSmallerSizes)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    auto res2 = buf.resize(5);
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(buf.size(), 5);
}

TEST(Buffer, AppendZeroLengthData)
{
    Buffer buf;
    auto res = buf.append(4);
    ASSERT_TRUE(res.has_value());
    auto res2 = buf.append(0);
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(buf.size(), 4);
}

TEST(Buffer, ClearGuard)
{
    Buffer buf;
    {
        BufferClearGuard guard(buf);
        auto res = buf.append(4);
        EXPECT_EQ(buf.size(), 4);
        ASSERT_TRUE(res.has_value());
    }
    ASSERT_TRUE(buf.empty());
}