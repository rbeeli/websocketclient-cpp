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

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#define WS_CLIENT_LOG_MSG_SIZES 1
#define WS_CLIENT_LOG_FRAMES 1
#define WS_CLIENT_LOG_PING_PONG 1
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;

asio::awaitable<expected<void, WSError>> run()
{
    // parse URL
    WS_CO_TRY(url_res, URL::parse("wss://echo.websocket.org/"));
    URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url.host(), "https", asio::use_awaitable);


    asio::ssl::context ctx(asio::ssl::context::tlsv13);
    ctx.set_default_verify_paths();
    ctx.set_options(
        asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
        asio::ssl::context::no_sslv3
    );
    ctx.set_verify_mode(asio::ssl::verify_peer);
    ctx.set_verify_callback(asio::ssl::host_name_verification(url.host()));

    std::cout << "Connecting to " << url.host() << "... \n";
    asio::ssl::stream<asio::ip::tcp::socket> socket(executor, ctx);
    co_await asio::async_connect(socket.lowest_layer(), endpoints, asio::use_awaitable);
    std::cout << "Connected\n";

    // Set SNI Hostname (many servers need this to handshake successfully)
    if (!SSL_set_tlsext_host_name(socket.native_handle(), "echo.websocket.org"))
    {
        asio::error_code ec{static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()};
        throw asio::system_error(ec);
    }

    co_await socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);
    std::cout << "Handshake ok\n";

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    auto asio_socket = AsioSocket(&logger, std::move(socket));

    // websocket client
    auto client = WebSocketClientAsync<asio::awaitable, decltype(logger), decltype(asio_socket)>(
        &logger, std::move(asio_socket)
    );

    // handshake handler
    auto handshake = Handshake(&logger, url);

    // start client
    WS_CO_TRYV(co_await client.init(handshake));

    Buffer buffer;
    for (int i = 0;; i++)
    {
        // automatically clear buffer on every iteration
        BufferClearGuard guard(buffer);

        // read message from server into buffer
        WS_CO_TRY(res_msg, co_await client.read_message(buffer));

        // write back to server
        string text = "This is the " + std::to_string(i) + "th message";
        Message msg2(MessageType::TEXT, text);
        WS_CO_TRYV(co_await client.send_message(msg2));
    }

    WS_CO_TRYV(co_await client.close());

    co_return expected<void, WSError>{};
};


int main()
{
    asio::io_context ctx;

    auto exception_handler = [&](auto e_ptr)
    {
        if (e_ptr)
            std::rethrow_exception(e_ptr);
    };

    auto client = []() -> asio::awaitable<void>
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
        }
    };

    asio::co_spawn(ctx, client, std::move(exception_handler));
    ctx.run();

    return 0;
}
