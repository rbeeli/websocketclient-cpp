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

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono;
using namespace std::chrono_literals;

/**
 * Quick and dirty way to extract a JSON property value.
 * Returns property value of first occurence of "property_name": [property_value].
 * Note that strings retain their quotes.
 */
std::string_view extract_json_property_value(
    const std::string_view& json, const std::string& property_name
)
{
    std::string searchKey = "\"" + property_name + "\":";
    size_t startPos = json.find(searchKey);
    if (startPos != std::string::npos)
    {
        startPos += searchKey.length();                     // move past the property_name
        size_t endPos = json.find_first_of(",}", startPos); // find the next comma or closing brace
        if (endPos != std::string::npos)
            return std::string_view(json).substr(startPos, endPos - startPos);
    }
    return "";
}

struct msg_stats
{
    uint64_t counter{0};
    size_t total_bytes{0};
    double avg_latency{0};
    void reset()
    {
        counter = 0;
        total_bytes = 0;
        avg_latency = 0;
    }
};

asio::awaitable<expected<void, WSError>> run()
{
    // parse URL
    WS_CO_TRY(url, URL::parse("wss://fstream.binance.com/ws"));

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(url->host(), "https", asio::use_awaitable);

    std::cout << "Connecting to " << url->host() << "... \n";

    asio::ssl::context ctx(asio::ssl::context::sslv23);
    ctx.set_default_verify_paths();
    asio::ssl::stream<asio::ip::tcp::socket> socket(executor, ctx);

    co_await asio::async_connect(socket.lowest_layer(), endpoints, asio::use_awaitable);

    std::cout << "Connected\n";

    socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
    socket.set_verify_mode(asio::ssl::verify_peer);
    socket.set_verify_callback(asio::ssl::host_name_verification(url->host()));
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
            "!ticker@arr",
            "btcusdt@depth@0ms",
            "btcusdt@bookTicker",
            "btcusdt@aggTrade",
            "ethusdt@depth@0ms",
            "ethusdt@bookTicker",
            "ethusdt@aggTrade",
            "xrpusdt@depth@0ms",
            "xrpusdt@bookTicker",
            "xrpusdt@aggTrade",
            "adausdt@depth@0ms",
            "adausdt@bookTicker",
            "adausdt@aggTrade",
            "solusdt@depth@0ms",
            "solusdt@bookTicker",
            "solusdt@aggTrade",
            "arbusdt@depth@0ms",
            "arbusdt@bookTicker",
            "arbusdt@aggTrade",
            "bnbusdt@depth@0ms",
            "bnbusdt@bookTicker",
            "bnbusdt@aggTrade",
            "avaxusdt@depth@0ms",
            "avaxusdt@bookTicker",
            "avaxusdt@aggTrade",
            "dogeusdt@depth@0ms",
            "dogeusdt@bookTicker",
            "dogeusdt@aggTrade",
            "aptusdt@depth@0ms",
            "aptusdt@bookTicker",
            "aptusdt@aggTrade"
        ],
        "id": 1
    })";
    Message msg(MessageType::text, sub_msg);
    WS_CO_TRYV(co_await client.send_message(msg, {.compress = false}));

    time_point<system_clock> last_msg;
    msg_stats stats;

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_CO_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (true)
    {
        ++stats.counter;

        auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var =
            co_await client.read_message(*buffer, 5s); // 5 sec timeout

        if (auto msg = std::get_if<Message>(&var))
        {
            stats.total_bytes += msg->data.size();

            auto E = std::atoll(extract_json_property_value(msg->to_string_view(), "E").data());
            auto latency = ms - E;
            stats.avg_latency += static_cast<double>(latency);

            auto t = system_clock::now();
            if (t - last_msg > 1s)
            {
                stats.avg_latency /= static_cast<double>(stats.counter);

                std::cout << std::setw(6) << stats.counter << " msg/s  ";
                std::cout << "avg latency " << std::setw(8) << stats.avg_latency << " ms  ";
                std::cout << "bytes recv " << stats.total_bytes << std::endl;

                stats.reset();
                last_msg = t;
            }
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D>("Ping frame received");
            WS_CO_TRYV(co_await client.send_pong_frame(ping_frame->payload_bytes()));
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
            // error occurred - must close connection
            logger.log<LogLevel::E>("Error: " + err->message);
            WS_CO_TRYV(co_await client.close(err->close_with_code));
            co_return expected<void, WSError>{};
        }
    }

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