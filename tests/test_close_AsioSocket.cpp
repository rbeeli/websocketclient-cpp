#include <iostream>
#include <signal.h>
#include <string>
#include <expected>
#include <variant>
#include <chrono>
#include <exception>

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
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono_literals;

asio::awaitable<expected<void, WSError>> run()
{
    // parse URL
    WS_CO_TRY(url_res, URL::parse("wss://localhost:9443"));
    URL& url = *url_res;

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url.host(), "9443", asio::use_awaitable);

    auto write_strand = asio::make_strand(executor);

    asio::ssl::context ctx(asio::ssl::context::tlsv12_client);
    ctx.load_verify_file("cert.pem");
    ctx.set_verify_mode(asio::ssl::verify_peer);
    ctx.set_verify_callback(asio::ssl::host_name_verification(url.host()));

    std::cout << "Connecting to " << url.host() << "... \n";
    asio::ssl::stream<asio::ip::tcp::socket> socket(executor, ctx);
    co_await asio::async_connect(socket.lowest_layer(), endpoints, asio::use_awaitable);
    std::cout << "Connected\n";

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

    // perform handshake
    WS_CO_TRYV(co_await client.handshake(handshake));

    // send message
    string payload = "test";
    Message msg(MessageType::text, payload);
    WS_CO_TRYV(co_await client.send_message(msg));

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_CO_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));
    
    for (int i = 0;; i++)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            co_await client.read_message(*buffer, 60s);

        if (std::get_if<Message>(&var))
        {
            // write message back to server
            string text = "This is the " + std::to_string(i) + "th message";
            Message msg2(MessageType::text, text);

            // // wait for server to close connection
            // asio::steady_timer timer(executor, std::chrono::seconds(1));
            // co_await timer.async_wait(asio::use_awaitable);

            co_await asio::co_spawn(
                write_strand,
                client.send_message(msg2),
                asio::use_awaitable
            );

            // auto res = co_await client.send_message(msg2);
            // if (!res.has_value())
            //     break;
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D>("Ping frame received");

            // send pong in parallel
            asio::co_spawn(
                write_strand,
                // don't capture ping_frame by value (or worse reference) -> creates lifetime issue,
                // see https://devblogs.microsoft.com/oldnewthing/20211103-00/?p=105870
                // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rcoro-capture
                [&client](PingFrame ping_frame) -> awaitable<void>
                { //
                    co_await client.send_pong_frame(ping_frame.payload_bytes());
                }(*ping_frame),
                asio::detached
            );

            // auto res = co_await client.send_pong_frame(ping_frame->payload_bytes());
            // if (!res.has_value())
            //     break;
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
                    "Close frame received: " + string(close_frame->get_reason())
                );
            }
            else
                logger.log<LogLevel::I>("Close frame received");
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {

            asio::co_spawn(
                write_strand,
                [&]() -> awaitable<void>
                {
                    logger.log<LogLevel::D>("Sending ping ...");
                    string ping_msg = R"({"op":"ping"})";
                    Message msg = Message(MessageType::text, ping_msg);
                    auto res = co_await client.send_message(msg, {.compress = false});
                    if (!res.has_value())
                        logger.log<LogLevel::E>("WSError: " + err->message);
                },
                asio::detached
            );

            // error occurred - must close connection
            logger.log<LogLevel::E>("WSError: " + err->message);

            // co_await client.close(err->close_with_code);
            co_await asio::co_spawn(
                write_strand,
                client.close(err->close_with_code),
                asio::use_awaitable
            );
            
            co_return std::unexpected{*err};
            // break;
        }
    }

    // // wait for server to close connection
    // asio::steady_timer timer(executor, std::chrono::seconds(1));
    // co_await timer.async_wait(asio::use_awaitable);

    // co_await client.close(close_code::normal_closure);

    co_await asio::co_spawn(
        write_strand,
        [&]() -> awaitable<void>
        {
            auto res = co_await client.close(close_code::normal_closure);
            if (!res.has_value())
                logger.log<LogLevel::E>("Error closing websocket client: " + res.error().message);
        },
        asio::use_awaitable
    );

    co_return expected<void, WSError>{};
};


int main()
{
    // single-threaded io_context
    // https://think-async.com/Asio/asio-1.22.0/doc/asio/overview/core/concurrency_hint.html
    asio::io_context ctx{1};

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
                std::cerr << "run() returned error: " << res.error().message << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << "run() returned exception: " << e.what() << std::endl;
        }
    };

    asio::co_spawn(ctx, client, std::move(exception_handler));
    ctx.run();

    return 0;
}
