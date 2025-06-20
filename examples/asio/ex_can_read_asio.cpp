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
using namespace std::chrono;

asio::awaitable<std::expected<void, WSError>> run()
{
    // websocketclient logger
    ConsoleLogger logger{LogLevel::D};
    logger.set_level(LogTopic::RecvFrame, LogLevel::D);

    // parse URL
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

    // subscribe
    std::string sub_msg = R"({
        "method": "SUBSCRIBE",
        "params": [
            "dogeusdt@aggTrade"
        ],
        "id": 1
    })";
    Message msg(MessageType::text, sub_msg);
    WS_CO_TRYV(co_await client.send_message(msg, {.compress = false}));

    time_point<system_clock> last_msg;

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_CO_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (true)
    {
        // for illustration, poll read state of socket until it can be read
        while (!client.can_read())
        {
            logger.log<LogLevel::D, LogTopic::TCP>("Waiting for data to read");
            co_await asio::steady_timer(executor, 500ms).async_wait(asio::use_awaitable);
        }

        auto t = std::chrono::steady_clock::now();

        // read message from server into buffer
        std::variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var =
            co_await client.read_message(
                *buffer, 5s
            ); // timeout is only for actually reading, we know there is data

        std::cout << "Read took "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - t
                     )
                         .count()
                  << " ms\n";

        if (auto msg = std::get_if<Message>(&var))
        {
            logger.log<LogLevel::I, LogTopic::RecvFrame>(
                std::format("Received {} bytes", msg->data.size())
            );
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D, LogTopic::RecvFrame>("Ping frame received");
            WS_CO_TRYV(
                co_await client.send_pong_frame(
                    ping_frame->payload_bytes(), std::chrono::seconds{10}
                )
            );
        }
        else if (std::get_if<PongFrame>(&var))
        {
            logger.log<LogLevel::D, LogTopic::RecvFrame>("Pong frame received");
        }
        else if (auto close_frame = std::get_if<CloseFrame>(&var))
        {
            // server initiated close
            if (close_frame->has_reason())
            {
                logger.log<LogLevel::I, LogTopic::RecvFrame>(
                    std::format("Close frame received: {}", close_frame->get_reason())
                );
            }
            else
                logger.log<LogLevel::I, LogTopic::RecvFrame>("Close frame received");
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            // check not timeout
            if (err->code == WSErrorCode::timeout_error)
            {
                logger.log<LogLevel::E, LogTopic::RecvFrame>(
                    "Timeout reading message, this should NOT happen!"
                );
                continue;
            }
            else
            {
                // error occurred - must close connection
                logger.log<LogLevel::E, LogTopic::RecvFrame>(err->to_string());
                WS_CO_TRYV(co_await client.close(err->close_with_code));
                co_return std::expected<void, WSError>{};
            }
        }
    }

    WS_CO_TRYV(co_await client.close(close_code::normal_closure));

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
        try
        {
            auto res = co_await run();
            if (!res.has_value())
                std::cerr << "Error: " << res.error() << std::endl;
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
