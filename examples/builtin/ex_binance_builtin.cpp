#include <iostream>
#include <string>
#include <format>
#include <variant>
#include <expected>
#include <chrono>
#include <algorithm>
#include <iomanip>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono;

/**
 * Quick and dirty way to extract a JSON property value.
 * Returns property value of first occurence of "property_name": [property_value].
 * Note that strings retain their quotes.
 */
std::string_view extract_json_property_value(
    const std::string_view& json, const std::string& property_name
)
{
    std::string searchKey = std::format("\"{}\":", property_name);
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

expected<void, WSError> run()
{
    // websocketclient logger
    ConsoleLogger logger{LogLevel::D};

    // parse URL
    WS_TRY(url, URL::parse("wss://fstream.binance.com/ws"));

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url->host(), url->port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // create TCP socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.set_SO_RCVBUF(1 * 1024 * 1024)); // 1 MB

    // SSL socket wrapper
    OpenSslContext ctx(&logger);
    WS_TRYV(ctx.init());
    WS_TRYV(ctx.set_default_verify_paths());
    auto ssl = OpenSslSocket(&logger, std::move(tcp), &ctx, url->host(), true);
    WS_TRYV(ssl.init());
    WS_TRYV(ssl.connect(2s)); // 2 sec connect timeout

    // websocket client
    auto client = WebSocketClient(&logger, std::move(ssl));

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
    WS_TRYV(client.handshake(handshake, 5s)); // 5 sec timeout

    // subscribe
    std::string sub_msg = R"({
        "method": "SUBSCRIBE",
        "params": [
            "btcusdt@depth@0ms",
            "btcusdt@bookTicker",
            "btcusdt@aggTrade",
            "ethusdt@depth@0ms",
            "ethusdt@bookTicker",
            "ethusdt@aggTrade"
        ],
        "id": 1
    })";
    Message msg(MessageType::text, sub_msg);
    WS_TRYV(client.send_message(msg, {.compress = false}));

    time_point<system_clock> last_msg;
    msg_stats stats;

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (true)
    {
        ++stats.counter;

        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(*buffer, 30s);                            // 30 sec timeout

        if (auto msg = std::get_if<Message>(&var))
        {
            stats.total_bytes += msg->data.size();

            auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
            auto E = std::atoll(extract_json_property_value(msg->to_string_view(), "E").data());
            auto latency = ms - E;
            stats.avg_latency += static_cast<double>(latency);

            auto t = system_clock::now();
            if (t - last_msg > seconds(1))
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
            logger.log<LogLevel::D, LogTopic::User>("Ping frame received");
            WS_TRYV(client.send_pong_frame(ping_frame->payload_bytes()));
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
            // error occurred - must close connection
            logger.log<LogLevel::E, LogTopic::User>(err->to_string());
            WS_TRYV(client.close(err->close_with_code));
            return {};
        }
    }

    return {};
};


int main()
{
    auto res = run();
    if (!res.has_value())
    {
        std::cerr << "Error: " << res.error() << std::endl;
        return 2;
    }
    return 0;
};