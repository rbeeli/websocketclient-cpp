#include <iostream>
#include <string>
#include <variant>
#include <chrono>
#include <signal.h>
#include <netinet/tcp.h>

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>

#define WS_CLIENT_LOG_HANDSHAKE 0
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#define WS_CLIENT_LOG_MSG_SIZES 0
#define WS_CLIENT_LOG_FRAMES 0

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono_literals;
using namespace asio;
using std::string;
using std::variant;
using std::span;
using std::byte;
using asio::awaitable;
using asio::ip::tcp;

[[nodiscard]] expected<void, WSError> check_errno(ssize_t error_code, const string& desc) noexcept
{
    if (error_code == -1)
    {
        int errno_ = errno;
        return WS_ERROR(
            uncategorized,
            "Error during " + desc + ": " + string(std::strerror(errno_)) + " (" +
                std::to_string(errno_) + ")",
            close_code::not_set
        );
    }
    return {};
}

[[nodiscard]] static awaitable<expected<string, WSError>> send_request(
    string url_str, bool read_response
)
{
    WS_CO_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(
        url.host(), std::to_string(url.port()), asio::use_awaitable
    );
    tcp::socket socket1(executor);
    co_await asio::async_connect(socket1, endpoints, asio::use_awaitable);

    ConsoleLogger<LogLevel::E> logger;
    auto socket = AsioSocket(&logger, std::move(socket1));
    auto client = WebSocketClientAsync<awaitable, decltype(logger), decltype(socket)>(
        &logger, std::move(socket)
    );
    auto handshake = Handshake(&logger, url);
    WS_CO_TRYV(co_await client.handshake(handshake));

    string response;
    if (read_response)
    {
        Buffer buffer;

        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            co_await client.read_message(buffer, 60s);

        if (auto msg = std::get_if<Message>(&var))
        {
            response = msg->to_string();
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            WS_CO_TRYV(co_await client.send_pong_frame(ping_frame->payload_bytes()));
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            std::cerr << "Error: " << err->message << std::endl;
        }
        else
            throw std::runtime_error("Unexpected message type");
    }

    WS_CO_TRYV(co_await client.close(close_code::normal_closure));

    co_return response;
}

[[nodiscard]] static awaitable<expected<void, WSError>> run_case(string url_str)
{
    WS_CO_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(
        url.host(), std::to_string(url.port()), asio::use_awaitable
    );
    tcp::socket socket1(executor);
    co_await asio::async_connect(socket1, endpoints, asio::use_awaitable);
    socket1.lowest_layer().set_option(tcp::no_delay(true));

    ConsoleLogger<LogLevel::E> logger;
    auto socket = AsioSocket(&logger, std::move(socket1));
    auto client = WebSocketClientAsync<awaitable, decltype(logger), decltype(socket)>(
        &logger, std::move(socket)
    );

    // handshake handler
    auto handshake = Handshake(&logger, url);

    // enable compression (permessage-deflate extension)
    handshake.set_permessage_deflate({
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    });

    // perform handshake
    WS_CO_TRYV(co_await client.handshake(handshake));

    Buffer buffer;
    buffer.set_max_size(100 * 1024 * 1024); // 100 MB
    while (true)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            co_await client.read_message(buffer, 60s);

        if (auto msg = std::get_if<Message>(&var))
        {
            // write message back to server
            WS_CO_TRYV(co_await client.send_message(*msg));
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            WS_CO_TRYV(co_await client.send_pong_frame(ping_frame->payload_bytes()));
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (std::holds_alternative<CloseFrame>(var))
        {
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            std::cerr << "Error: " << err->message << std::endl;
            WS_CO_TRYV(co_await client.close(err->close_with_code));
            break;
        }
        else
            throw std::runtime_error("Unexpected message type");
    }

    WS_CO_TRYV(co_await client.close(close_code::normal_closure));

    co_return expected<void, WSError>{};
}

awaitable<void> client()
{
    string agent = WS_AUTOBAHN_AGENT_NAME;
    string host = "127.0.0.1:9001";
    int case_count = 0;

    // getCaseCount
    {
        auto res = co_await send_request("ws://" + host + "/getCaseCount", true);
        if (!res.has_value())
        {
            std::cerr << "Failed to fetch cases count: " << res.error() << std::endl;
            co_return;
        }
        auto& str = res.value();
        auto case_count_conv = std::from_chars(str.data(), str.data() + str.size(), case_count);
        if (case_count_conv.ec != std::errc{})
        {
            std::cerr << "Failed to parse number of cases: " << str << std::endl;
            co_return;
        }
    }

    // run cases
    for (int i = 1; i <= case_count; ++i)
    {
        // getCaseInfo
        {
            auto res = co_await send_request(
                "ws://" + host + "/getCaseInfo?case=" + std::to_string(i), true
            );
            if (!res.has_value())
            {
                std::cerr << "Failed to fetch case info: " << res.error() << std::endl;
                co_return;
            }
            std::cout << res.value() << std::endl;
        }

        string url = "ws://" + host + "/runCase?case=" + std::to_string(i) + "&agent=" + agent;
        auto res_case = co_await run_case(url);
        if (!res_case.has_value())
            std::cerr << "Case " << i << ": " << res_case.error() << std::endl;
    }

    std::cout << "Cases processed, updating reports..." << std::endl;

    // updateReports
    {
        auto res = co_await send_request("ws://" + host + "/updateReports?agent=" + agent, false);
        if (!res.has_value())
        {
            std::cerr << "Failed to update reports: " << res.error() << std::endl;
            co_return;
        }
    }

    std::cout << "Autobahn tests finished" << std::endl;

    co_return;
}

int main()
{
    // https://think-async.com/Asio/asio-1.22.0/doc/asio/overview/core/concurrency_hint.html
    auto ctx = asio::io_context{ASIO_CONCURRENCY_HINT_UNSAFE_IO};

    auto exception_handler = [&](auto e_ptr)
    {
        if (e_ptr)
        {
            std::rethrow_exception(e_ptr);
        }
    };

    asio::co_spawn(ctx, client, std::move(exception_handler));
    ctx.run();

    return 0;
};