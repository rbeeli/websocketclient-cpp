#include <iostream>
#include <string>
#include <chrono>
#include <algorithm>
#include <iomanip>

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#define WS_CLIENT_LOG_MSG_SIZES 0
#define WS_CLIENT_LOG_FRAMES 0
#define WS_CLIENT_LOG_PING_PONG 1
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;

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

expected<void, WSError> run()
{
    // parse URL
    WS_TRY(url_res, URL::parse("wss://fstream.binance.com/ws"));
    URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // create socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.set_TCP_NODELAY(true));
    WS_TRYV(tcp.set_TCP_QUICKACK(true));
    WS_TRYV(tcp.set_SO_RCVBUF(1 * 1024 * 1024)); // 1 MB
    WS_TRYV(tcp.connect());

    // SSL socket wrapper
    OpenSslContext ctx(&logger);
    WS_TRYV(ctx.init());
    WS_TRYV(ctx.set_default_verify_paths());
    auto ssl = OpenSslSocket(&logger, tcp.get_fd(), &ctx, url.host(), true);
    WS_TRYV(ssl.init());
    WS_TRYV(ssl.connect());

    // websocket client
    auto client = WebSocketClient(&logger, std::move(ssl));

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
    WS_TRYV(client.init(handshake));

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
    Message msg(MessageType::TEXT, sub_msg);
    WS_TRYV(client.send_message(msg, {.compress = false}));

    std::chrono::time_point<std::chrono::system_clock> last_msg;
    msg_stats stats;

    Buffer buffer;
    while (true)
    {
        // automatically clear buffer on every iteration
        BufferClearGuard guard(buffer);

        ++stats.counter;

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()
        )
                      .count();

        WS_TRY(res, client.read_message(buffer));
        Message& msg = *res;

        stats.total_bytes += msg.data.size();

        auto E = std::atoll(extract_json_property_value(msg.to_string_view(), "E").data());
        auto latency = ms - E;
        stats.avg_latency += static_cast<double>(latency);

        auto t = std::chrono::system_clock::now();
        if (t - last_msg > std::chrono::seconds(1))
        {
            stats.avg_latency /= static_cast<double>(stats.counter);

            std::cout << std::setw(6) << stats.counter << " msg/s  ";
            std::cout << "avg latency " << std::setw(8) << stats.avg_latency << " ms  ";
            std::cout << "bytes recv " << stats.total_bytes << std::endl;

            stats.reset();
            last_msg = t;
        }
    }

    return {};
};


int main()
{
    auto res = run();
    if (!res.has_value())
    {
        std::cerr << "Error: " << res.error().message << std::endl;
        return 2;
    }
    return 0;
};