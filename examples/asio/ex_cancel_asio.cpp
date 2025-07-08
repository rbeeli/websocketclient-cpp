#include <iostream>
#include <signal.h>
#include <string>
#include <format>
#include <chrono>
#include <exception>

#include <asio.hpp>
#include <asio/read_until.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/WebSocketClientAsync.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::literals::chrono_literals;
using namespace asio::experimental::awaitable_operators;


asio::awaitable<std::expected<void, WSError>> run()
{
    // websocketclient logger
    ConsoleLogger logger{LogLevel::D};
    logger.set_level(LogTopic::DNS, LogLevel::D);
    logger.set_level(LogTopic::TCP, LogLevel::D);
    logger.set_level(LogTopic::Handshake, LogLevel::D);

    WS_CO_TRY(url, URL::parse("wss://fstream.binance.com/ws"));

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url->host(), "https", asio::use_awaitable);

    std::cout << "Connecting to " << url->host() << "... \n";

    asio::ssl::context ctx(asio::ssl::context::tls);
    ctx.set_default_verify_paths();
    asio::ssl::stream<asio::ip::tcp::socket> socket(executor, ctx);

    co_await asio::async_connect(socket.lowest_layer(), endpoints, asio::use_awaitable);

    std::cout << "Connected\n";

    // disable Nagle's algorithm
    socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));

    // enable verification of the server certificate
    socket.set_verify_mode(asio::ssl::verify_peer);

    // enable host name verification
    socket.set_verify_callback(asio::ssl::host_name_verification(url->host()));

    // tell server the vhost (many hosts need this to handshake successfully)
    SSL_set_tlsext_host_name(socket.native_handle(), url->host().c_str());

    co_await socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

    std::cout << "Handshake ok\n";

    auto asio_socket = AsioSocket(&logger, std::move(socket));

    // websocket client
    auto client = WebSocketClientAsync<asio::awaitable, decltype(logger), decltype(asio_socket)>(
        &logger, std::move(asio_socket)
    );

    // handshake handler
    auto handshake = Handshake(&logger, *url);

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

    // perform handshake
    WS_CO_TRYV(co_await client.handshake(handshake, 5s)); // 5 sec timeout

    // we don't subscribe so it looks like we are not receiving any messages
    // std::string sub_msg = R"({
    //     "method": "SUBSCRIBE",
    //     "params": ["btcusdt@aggTrade"],
    //     "id": 1
    // })";
    // Message msg(MessageType::text, sub_msg);
    // WS_CO_TRYV(co_await client.send_message(msg, {.compress = false}));

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_CO_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (client.is_open())
    {
        asio::cancellation_signal cancel;

        // this is not super safe (detached), but good enough for demonstration here
        asio::co_spawn(
            executor,
            ([](asio::any_io_executor io, asio::cancellation_signal& cancel) -> asio::awaitable<void>
            {
                // wait 3 seconds
                asio::steady_timer t(io);
                t.expires_after(3s);
                co_await t.async_wait(asio::use_awaitable);

                // fire cancel signal
                std::cout << "Cancelling operation..." << std::endl;
                cancel.emit(asio::cancellation_type::all);

                co_return;
            })(executor, cancel),
            asio::detached
        );

        // read message from server into buffer
        std::variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var =
            co_await client.read_message(
                *buffer, 9999s, cancel.slot() // don't run into timeout, cancel will trigger
            );

        if (auto msg = std::get_if<Message>(&var))
        {
            std::cout << msg->to_string() << std::endl;
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D, LogTopic::User>("Ping frame received");
            WS_CO_TRYV(co_await client.send_pong_frame(ping_frame->payload_bytes()));
        }
        else if (std::get_if<PongFrame>(&var))
        {
            logger.log<LogLevel::D, LogTopic::User>("Pong frame received");
        }
        else if (auto close_frame = std::get_if<CloseFrame>(&var))
        {
            // server initiated close
            if (close_frame->has_reason())
            {
                logger.log<LogLevel::I, LogTopic::User>(
                    std::format("Close frame received: {}", close_frame->get_reason())
                );
            }
            else
                logger.log<LogLevel::I, LogTopic::User>("Close frame received");
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            if (err->code == WSErrorCode::timeout_error)
            {
                std::cout << "read_message timed out\n";
                break;
            }

            // error occurred - must close connection
            logger.log<LogLevel::E, LogTopic::User>(err->to_string());
            WS_CO_TRYV(co_await client.close(err->close_with_code));
            co_return std::expected<void, WSError>{};
        }
    }

    co_await client.close(close_code::normal_closure);

    co_return std::expected<void, WSError>{};
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
        // loop to restart the client after an error
        while (true)
        {
            try
            {
                auto res = co_await run();
                if (!res.has_value())
                    std::cerr << "Error: " << res.error() << std::endl;
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

    asio::co_spawn(ctx, client, std::move(exception_handler));
    ctx.run();

    std::cout << "Done\n";

    return 0;
}