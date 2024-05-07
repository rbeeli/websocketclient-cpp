#include <iostream>
#include <signal.h>
#include <string>
#include <chrono>

#define ASIO_STANDALONE 1
#define ASIO_NO_TYPEID 1

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>

#define WS_CLIENT_VALIDATE_UTF8 1

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#define WS_CLIENT_LOG_MSG_SIZES 1
#define WS_CLIENT_LOG_FRAMES 1

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/WebSocketClientAsync.hpp"
#include "ws_client/ws_client.hpp"

using namespace ws_client;
using namespace asio;
using std::string;
using std::span;
using std::byte;
using asio::awaitable;
using asio::ip::tcp;

awaitable<void> client()
{
    // string url_raw = "wss://echo.websocket.org";
    string url_raw = "wss://fstream.binance.com/stream?streams=!ticker@arr/btcusdt@depth@0ms/"
                     "btcusdt@bookTicker/btcusdt@aggTrade";
    // string url_raw = "wss://localhost:9443";
    // string url_raw = "ws://localhost:8080";

    auto url_res = URL::parse(url_raw);
    URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url.host(), "https", asio::use_awaitable);

    std::cout << "Connecting to " << url.host() << "... \n";

    asio::ssl::context ctx(asio::ssl::context::sslv23);
    ctx.set_default_verify_paths();
    asio::ssl::stream<asio::ip::tcp::socket> socket(executor, ctx);

    std::cout << "Connected\n";

    co_await asio::async_connect(socket.lowest_layer(), endpoints, asio::use_awaitable);
    socket.lowest_layer().set_option(tcp::no_delay(true));
    socket.set_verify_mode(asio::ssl::verify_peer);
    socket.set_verify_callback(asio::ssl::host_name_verification(url.host()));
    co_await socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

    std::cout << "Handshake ok\n";

    auto asio_socket = AsioSocket(std::move(socket));

    // websocket client
    auto client =
        WebSocketClientAsync<awaitable, AsioSocket<asio::ssl::stream<asio::ip::tcp::socket>>>(
            asio_socket
        );

    // handshake handler
    auto handshake = Handshake(url);

    // start client
    auto res = co_await client.init(handshake);
    if (!res.has_value())
    {
        std::cerr << "Error: " << res.error().message << std::endl;
        co_return;
    }

    Buffer buffer;
    bool continue_reading = true;
    while (continue_reading)
    {
        auto res2 = co_await client.read_message(buffer);
        if (!res2.has_value())
        {
            std::cerr << "Error: " << res2.error().message << std::endl;
            continue;
        }
        // Message& msg = *res2;
        // // Message msg = Message::from_string("", MessageType::TEXT);
        // auto res3 = co_await client.send_message(msg);
        // if (!res3.has_value())
        // {
        //     std::cerr << "Error: " << res3.error().message << std::endl;
        //     continue;
        // }

        buffer.clear();
    }

    auto res4 = co_await client.close();
    if (!res4.has_value())
    {
        std::cerr << "Error: " << res4.error().message << std::endl;
        co_return;
    }

    co_return;
}

int main()
{
    // https://think-async.com/Asio/asio-1.22.0/doc/asio/overview/core/concurrency_hint.html
    auto ctx = asio::io_context{ASIO_CONCURRENCY_HINT_UNSAFE_IO};
    // auto guard = asio::make_work_guard(ctx.get_executor());

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
}