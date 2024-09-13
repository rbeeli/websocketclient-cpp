#include <iostream>
#include <signal.h>
#include <string>
#include <format>
#include <variant>
#include <chrono>
#include <exception>

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;

asio::awaitable<expected<void, WSError>> run()
{
    // parse URL
    WS_CO_TRY(url, URL::parse("wss://echo.websocket.org/"));

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url->host(), "https", asio::use_awaitable);


    asio::ssl::context ctx(asio::ssl::context::tlsv13);
    ctx.set_default_verify_paths();
    ctx.set_options(
        asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
        asio::ssl::context::no_sslv3
    );
    ctx.set_verify_mode(asio::ssl::verify_peer);
    ctx.set_verify_callback(asio::ssl::host_name_verification(url->host()));

    std::cout << "Connecting to " << url->host() << "... \n";
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
    auto handshake = Handshake(&logger, *url);

    // perform handshake
    WS_CO_TRYV(co_await client.handshake(handshake, 5s)); // 5 sec timeout

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_CO_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    for (int i = 0;; i++)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var =
            co_await client.read_message(*buffer, 5s); // 5 sec timeout

        if (std::get_if<Message>(&var))
        {
            // write message back to server
            string text = std::format("This is the {}th message", i);
            Message msg2(MessageType::text, text);
            WS_CO_TRYV(co_await client.send_message(msg2));
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D>("Ping frame received");
            WS_CO_TRYV(co_await client.send_pong_frame(
                ping_frame->payload_bytes(), std::chrono::seconds{10}
            ));
        }
        else if (std::get_if<PongFrame>(&var))
        {
            logger.log<LogLevel::D>("Pong frame received");
        }
        else if (auto close_frame = std::get_if<CloseFrame>(&var))
        {
            // server initiated close
            if (close_frame->has_reason())
            {
                logger.log<LogLevel::I>(
                    std::format("Close frame received: {}", close_frame->get_reason())
                );
            }
            else
                logger.log<LogLevel::I>("Close frame received");
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            // error occurred - must close connection
            logger.log<LogLevel::E>(std::format("Error: {}", err->message));
            WS_CO_TRYV(co_await client.close(err->close_with_code));
            co_return expected<void, WSError>{};
        }
    }

    WS_CO_TRYV(co_await client.close(close_code::normal_closure));

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
