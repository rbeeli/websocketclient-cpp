#include <iostream>
#include <signal.h>
#include <string>
#include <chrono>

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#define WS_CLIENT_LOG_MSG_SIZES 0
#define WS_CLIENT_LOG_FRAMES 0
#define WS_CLIENT_LOG_PING_PONG 1
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/WebSocketClientAsync.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace asio;
using namespace std::literals::chrono_literals;
using namespace asio::experimental::awaitable_operators;


awaitable<expected<void, WSError>> run()
{
    WS_CO_TRY(url_res, URL::parse("wss://fstream.binance.com/ws"));
    URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url.host(), "https", use_awaitable);

    std::cout << "Connecting to " << url.host() << "... \n";

    ssl::context ctx(ssl::context::sslv23);
    ctx.set_default_verify_paths();
    ssl::stream<ip::tcp::socket> socket(executor, ctx);

    std::cout << "Connected\n";

    co_await asio::async_connect(socket.lowest_layer(), endpoints, use_awaitable);
    socket.lowest_layer().set_option(ip::tcp::no_delay(true));
    socket.set_verify_mode(ssl::verify_peer);
    socket.set_verify_callback(ssl::host_name_verification(url.host()));
    co_await socket.async_handshake(ssl::stream_base::client, use_awaitable);

    std::cout << "Handshake ok\n";

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    auto asio_socket = AsioSocket(&logger, std::move(socket));

    // websocket client
    auto client = WebSocketClientAsync<awaitable, decltype(logger), decltype(asio_socket)>(
        &logger, std::move(asio_socket)
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
        .decompress_buffer_size = 2 * 1024 * 1024, // 2 MB
        .compress_buffer_size = 2 * 1024 * 1024    // 2 MB
    });

    // start client
    WS_CO_TRYV(co_await client.init(handshake));

    // subscribe
    // we don't subscribe so it looks like we are not receiving any messages
    // std::string sub_msg = R"({
    //     "method": "SUBSCRIBE",
    //     "params": ["btcusdt@aggTrade"],
    //     "id": 1
    // })";
    // Message msg(MessageType::TEXT, sub_msg);
    // WS_CO_TRYV(co_await client.send_message(msg, {.compress = false}));

    Buffer buffer;
    while (client.is_open())
    {
        // automatically clear buffer on every iteration
        BufferClearGuard guard(buffer);

        // timeout after 5 seconds
        // https://cppalliance.org/asio/2023/01/02/Asio201Timeouts.html
        asio::steady_timer to{executor, 5s};
        auto res = co_await (to.async_wait(asio::use_awaitable) || client.read_message(buffer));
        if (res.index() == 0)
        {
            std::cout << "read_message timed out\n";
            break;
        }

        // read_message result
        auto& res_msg = std::get<1>(res);
        if (!res_msg.has_value())
        {
            std::cout << "Error: " << res_msg.error().message << std::endl;
            break;
        }

        Message& msg = *res_msg;
        std::cout << msg.to_string() << std::endl;
    }

    co_await client.close();

    co_return expected<void, WSError>{};
};


int main()
{
    // https://think-async.com/Asio/asio-1.22.0/doc/asio/overview/core/concurrency_hint.html
    auto ctx = asio::io_context{ASIO_CONCURRENCY_HINT_UNSAFE_IO};

    auto exception_handler = [&](auto e_ptr)
    {
        if (e_ptr)
            std::rethrow_exception(e_ptr);
    };

    auto client = []() -> awaitable<void>
    {
        // loop to restart the client after an error
        while (true)
        {
            try
            {
                auto res = co_await run();
                if (!res.has_value())
                    std::cerr << "Error: " << res.error().message << std::endl;
            }
            catch (const std::exception& e)
            {
                std::cerr << "Exception: " << e.what() << std::endl;

                // reconnect after 1 second
                std::clog << "Reconnecting in 1 second..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    };

    co_spawn(ctx, client, std::move(exception_handler));
    ctx.run();

    std::cout << "Done\n";

    return 0;
}