#include <gtest/gtest.h>

#include <string>
#include <span>
#include <iostream>

#include "ws_client/utils/CircularBuffer.hpp"

using namespace ws_client;
using std::span;

TEST(CircularBuffer, clear)
{
    CircularBuffer<int> buffer(8);

    EXPECT_TRUE(buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.size() == 0);

    buffer.push(1);

    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.size() == 1);

    buffer.clear();

    EXPECT_TRUE(buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.size() == 0);
}

TEST(CircularBuffer, push_pop_single_item)
{
    ws_client::CircularBuffer<int> buffer(8);
    buffer.push(42);
    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.size() == 1);

    int item = 0;
    EXPECT_TRUE(buffer.pop(item));
    EXPECT_TRUE(item == 42);
    EXPECT_TRUE(buffer.empty());
}

TEST(CircularBuffer, remove_n_items)
{
    ws_client::CircularBuffer<int> buffer(8);
    buffer.push(1);
    buffer.push(2);
    buffer.push(3);
    buffer.push(4);
    buffer.push(5);
    buffer.move_tail(3);
    EXPECT_TRUE(buffer.size() == 2);
    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer[0] == 4);
    EXPECT_TRUE(buffer[1] == 5);
}

TEST(CircularBuffer, push_multiple_without_wrap_around)
{
    ws_client::CircularBuffer<int> buffer(8);
    int itemsToPush[] = {1, 2, 3};
    buffer.push(itemsToPush, 3);
    EXPECT_TRUE(buffer.size() == 3);
    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.available() == 5);
    EXPECT_TRUE(buffer[0] == 1);
    EXPECT_TRUE(buffer[1] == 2);
    EXPECT_TRUE(buffer[2] == 3);
}

TEST(CircularBuffer, push_pop_multiple_with_wrap_around)
{
    ws_client::CircularBuffer<int> buffer(4);
    buffer.push(1);
    buffer.push(2);
    buffer.move_tail(2);
    int items[] = {3, 4, 5, 6};
    buffer.push(items, 4);
    EXPECT_TRUE(buffer.size() == 4);
    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(buffer.full());
    EXPECT_TRUE(buffer.available() == 0);
    EXPECT_TRUE(buffer[0] == 3);
    EXPECT_TRUE(buffer[1] == 4);
    EXPECT_TRUE(buffer[2] == 5);
    EXPECT_TRUE(buffer[3] == 6);
}

TEST(CircularBuffer, push_span)
{
    ws_client::CircularBuffer<int> buffer(8);
    int items[] = {1, 2, 3, 4, 5};
    span<int> items_span(items, 5);
    buffer.push(items_span);
    EXPECT_TRUE(buffer.size() == 5);
    EXPECT_TRUE(!buffer.empty());
    EXPECT_TRUE(!buffer.full());
    EXPECT_TRUE(buffer.available() == 3);
    EXPECT_TRUE(buffer[0] == 1);
    EXPECT_TRUE(buffer[1] == 2);
    EXPECT_TRUE(buffer[2] == 3);
    EXPECT_TRUE(buffer[3] == 4);
    EXPECT_TRUE(buffer[4] == 5);
}

TEST(CircularBuffer, pop_span)
{
    ws_client::CircularBuffer<int> buffer(8);

    int items[] = {1, 2, 3, 4, 5};
    buffer.push(items, 5);

    int popped[5];
    span<int> popped_span(popped, 5);
    buffer.pop(popped_span);
    EXPECT_TRUE(popped[0] == 1);
    EXPECT_TRUE(popped[1] == 2);
    EXPECT_TRUE(popped[2] == 3);
    EXPECT_TRUE(popped[3] == 4);
    EXPECT_TRUE(popped[4] == 5);
    EXPECT_TRUE(buffer.empty());
}


TEST(CircularBuffer, available_as_contiguous_span_with_no_wrap_around)
{
    CircularBuffer<int> buffer(8);

    // fill half of the buffer to avoid wrap-around
    for (auto i = 1; i <= 6; ++i)
        buffer.push(i);

    buffer.move_tail(2);

    auto span = buffer.available_as_contiguous_span();
    EXPECT_TRUE(span.size() == 2); // expect 2 available until end since we added 6 already

    // verify that we can write to the span directly
    span[0] = 7;
    span[1] = 8;
    buffer.move_head(2);
    EXPECT_TRUE(buffer.size() == 6);
    EXPECT_TRUE(buffer[0] == 3);
    EXPECT_TRUE(buffer[1] == 4);
    EXPECT_TRUE(buffer[2] == 5);
    EXPECT_TRUE(buffer[3] == 6);
    EXPECT_TRUE(buffer[4] == 7);
    EXPECT_TRUE(buffer[5] == 8);
}

TEST(CircularBuffer, available_as_contiguous_span_with_wrap_around)
{
    CircularBuffer<int> buffer(2); // Smaller buffer to easily trigger wrap-around
    buffer.push(1);
    buffer.move_tail(1);
    buffer.push(2);
    buffer.push(3); // This will cause wrap-around
    buffer.move_tail(1);

    auto span = buffer.available_as_contiguous_span();
    EXPECT_TRUE(span.size() == 1); // Only 1 position available before wrap-around
}

TEST(CircularBuffer, move_head_updates_head_correctly)
{
    CircularBuffer<int> buffer(8);
    buffer.push(1);
    buffer.push(2);

    buffer.move_head(2);             // Simulate having written 2 more items directly
    EXPECT_TRUE(buffer.size() == 4); // Buffer size should reflect the moved head
    EXPECT_TRUE(!buffer.full());
}

// ---------------------------------------------------------------------------
//  Additional tests for span helpers when the buffer is full
// ---------------------------------------------------------------------------

TEST(CircularBuffer, AvailableSpanIsZeroWhenFull)
{
    CircularBuffer<int> buffer(4);

    int src[] = {1, 2, 3, 4};
    buffer.push(src, 4); // fill → full

    ASSERT_TRUE(buffer.full());
    auto avail = buffer.available_as_contiguous_span();
    EXPECT_EQ(avail.size(), 0u); // nothing writable
}

TEST(CircularBuffer, UsedSpanWhenFull_NoWrap)
{
    CircularBuffer<int> buffer(4);

    int src[] = {1, 2, 3, 4};
    buffer.push(src, 4); // head_ == tail_ == 0, full

    auto used = buffer.used_as_contiguous_span();
    ASSERT_EQ(used.size(), 4u); // whole array is readable
    for (int i = 0; i < 4; ++i)
        EXPECT_EQ(used[i], src[i]);
}

TEST(CircularBuffer, UsedSpanWhenFull_WrapAround)
{
    CircularBuffer<int> buffer(4);

    int first[] = {1, 2, 3, 4};
    buffer.push(first, 4); // full, head_ == 0
    buffer.move_tail(2);   // tail_  = 2, size = 2

    int second[] = {5, 6};
    buffer.push(second, 2); // wraps, full again (head_ == tail_ == 2)

    ASSERT_TRUE(buffer.full());
    auto used = buffer.used_as_contiguous_span();
    EXPECT_EQ(used.size(), 2u); // capacity - tail_  (4-2)
    EXPECT_EQ(used[0], 3);
    EXPECT_EQ(used[1], 4);
}
