#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <expected>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#define ASIO_NO_TYPEID 1
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>

#include "ws_client/Buffer.hpp"
#include "ws_client/BufferedSocket.hpp"
#include "ws_client/BufferedSocketAsync.hpp"

namespace
{
using ws_client::WSError;
using ws_client::byte;

struct SocketState
{
    explicit SocketState(std::string_view data) : input(data.size())
    {
        std::memcpy(input.data(), data.data(), data.size());
    }

    std::expected<size_t, WSError> read_some(std::span<byte> buffer) noexcept
    {
        size_t size = std::min(buffer.size(), input.size() - offset);
        std::copy_n(input.data() + offset, size, buffer.data());
        offset += size;
        return size;
    }

    std::vector<byte> input;
    size_t offset{0};
    size_t readiness_checks{0};
};

struct FakeSocket
{
    explicit FakeSocket(std::shared_ptr<SocketState> state) : state(std::move(state))
    {
    }

    std::expected<bool, WSError> wait_readable(ws_client::Timeout<>&) noexcept
    {
        ++state->readiness_checks;
        return false;
    }

    std::expected<size_t, WSError> read_some(std::span<byte> buffer, ws_client::Timeout<>&) noexcept
    {
        return state->read_some(buffer);
    }

    std::expected<size_t, WSError>
    write_some(std::span<byte> buffer, ws_client::Timeout<>&) noexcept
    {
        return buffer.size();
    }

    std::expected<void, WSError> shutdown(bool, ws_client::Timeout<>&) noexcept
    {
        return {};
    }

    std::expected<void, WSError> close(bool) noexcept
    {
        return {};
    }

    std::shared_ptr<SocketState> state;
};

struct FakeSocketAsync
{
    explicit FakeSocketAsync(std::shared_ptr<SocketState> state) : state(std::move(state))
    {
    }

    std::expected<bool, WSError> can_read() noexcept
    {
        ++state->readiness_checks;
        return false;
    }

    asio::awaitable<std::expected<size_t, WSError>>
    read_some(std::span<byte> buffer, ws_client::Timeout<>&) noexcept
    {
        co_return state->read_some(buffer);
    }

    asio::awaitable<std::expected<size_t, WSError>>
    write_some(std::span<byte> buffer, ws_client::Timeout<>&) noexcept
    {
        co_return buffer.size();
    }

    asio::awaitable<std::expected<void, WSError>> shutdown(bool, ws_client::Timeout<>&) noexcept
    {
        co_return std::expected<void, WSError>{};
    }

    asio::awaitable<std::expected<void, WSError>> close(bool) noexcept
    {
        co_return std::expected<void, WSError>{};
    }

    std::shared_ptr<SocketState> state;
};

constexpr std::string_view response = "HTTP/1.1 101 Switching Protocols\r\n\r\nframe";
constexpr std::array expected_frame{byte{'f'}, byte{'r'}, byte{'a'}, byte{'m'}, byte{'e'}};
} // namespace

TEST(BufferedSocket, buffered_data_is_immediately_readable)
{
    auto state = std::make_shared<SocketState>(response);
    ws_client::BufferedSocket socket{FakeSocket{state}};
    ws_client::Timeout<> timeout{std::chrono::seconds{1}};
    auto headers = ws_client::Buffer::create(0, 1024);
    ASSERT_TRUE(headers.has_value());

    std::array delimiter{byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
    ASSERT_TRUE(socket.read_until(*headers, std::span{delimiter}, timeout).has_value());
    std::array<byte, delimiter.size()> terminator;
    ASSERT_TRUE(socket.read_exact(terminator, timeout).has_value());

    EXPECT_EQ(socket.wait_readable(timeout), true);
    EXPECT_EQ(state->readiness_checks, 0);

    std::array<byte, expected_frame.size()> frame;
    ASSERT_TRUE(socket.read_exact(frame, timeout).has_value());
    EXPECT_EQ(frame, expected_frame);
    EXPECT_EQ(socket.wait_readable(timeout), false);
    EXPECT_EQ(state->readiness_checks, 1);
}

TEST(BufferedSocket, read_until_delimiter_spanning_full_reads)
{
    // delimiter starts at the end of a full 4096-byte read buffer and ends in the next read
    std::string data(4093, 'A');
    data += "\r\n\r\n";
    data += std::string(4095, 'B');
    auto state = std::make_shared<SocketState>(data);
    ws_client::BufferedSocket socket{FakeSocket{state}};
    ws_client::Timeout<> timeout{std::chrono::seconds{1}};
    auto headers = ws_client::Buffer::create(0, 1024 * 1024);
    ASSERT_TRUE(headers.has_value());

    std::array delimiter{byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
    ASSERT_TRUE(socket.read_until(*headers, std::span{delimiter}, timeout).has_value());
    EXPECT_EQ(headers->size(), 4093);

    std::array<byte, delimiter.size()> terminator;
    ASSERT_TRUE(socket.read_exact(terminator, timeout).has_value());
    EXPECT_EQ(terminator, delimiter);

    std::vector<byte> rest(4095);
    ASSERT_TRUE(socket.read_exact(rest, timeout).has_value());
    EXPECT_TRUE(std::all_of(rest.begin(), rest.end(), [](byte b) { return b == byte{'B'}; }));
}

TEST(BufferedSocketAsync, buffered_data_is_immediately_readable)
{
    auto state = std::make_shared<SocketState>(response);
    asio::io_context context;
    std::exception_ptr exception;

    asio::co_spawn(
        context,
        [state]() -> asio::awaitable<void>
        {
            ws_client::BufferedSocketAsync<FakeSocketAsync, asio::awaitable> socket{
                FakeSocketAsync{state}
            };
            ws_client::Timeout<> timeout{std::chrono::seconds{1}};
            auto headers = ws_client::Buffer::create(0, 1024);
            EXPECT_TRUE(headers.has_value());
            if (!headers.has_value())
                co_return;

            std::array delimiter{byte{'\r'}, byte{'\n'}, byte{'\r'}, byte{'\n'}};
            EXPECT_TRUE((co_await socket.read_until(*headers, delimiter, timeout)).has_value());
            std::array<byte, delimiter.size()> terminator;
            EXPECT_TRUE((co_await socket.read_exact(terminator, timeout)).has_value());

            EXPECT_EQ(socket.can_read(), true);
            EXPECT_EQ(state->readiness_checks, 0);

            std::array<byte, expected_frame.size()> frame;
            EXPECT_TRUE((co_await socket.read_exact(frame, timeout)).has_value());
            EXPECT_EQ(frame, expected_frame);
            EXPECT_EQ(socket.can_read(), false);
            EXPECT_EQ(state->readiness_checks, 1);
        },
        [&exception](std::exception_ptr result) { exception = result; }
    );

    context.run();
    EXPECT_EQ(exception, nullptr);
}
