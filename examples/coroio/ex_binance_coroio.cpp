#include <iostream>
#include <signal.h>
#include <string>
#include <chrono>

#include "coroio/all.hpp"

#include "ws_client/ws_client_async.hpp"
#include "ws_client/PermessageDeflate.hpp"
#include "ws_client/transport/CoroioSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

using namespace ws_client;
using namespace std::chrono_literals;
using namespace NNet;
using Loop = NNet::TLoop<NNet::TEPoll>;

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

TValueTask<expected<void, WSError>> client(Loop* loop)
{
    // parse URL
    WS_CO_TRY(url_res, URL::parse("wss://fstream.binance.com/ws"));
    URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_CO_TRY(dns_res, dns.resolve(url.host(), url.port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // TAddress address(&addr.address.addr, addr.ai_addrlen);
    // TAddress addr2(addr.address.addr, addr.ai_addrlen);
    TAddress addr2{addr.ip(), addr.port()};
    // TAddress addr2{"3.112.103.27", 443};

    // // resolve hostname
    // TResolver<TPollerBase> resolver(loop->Poller());
    // auto addrs = co_await resolver.Resolve(url.host());
    // std::cout << "'" << url.host() << "': ";
    // TAddress addr = addrs[0].WithPort(url.port());
    // // for (auto& a : addrs)
    // // {
    // //     addr = std::move(a.WithPort(url.port()));
    // //     std::cout << a.ToString() << "\n";
    // // }

    // ssl socket
    TSslContext ctx = TSslContext::Client([&](const char* s) { std::cerr << s << "\n"; });
    TSocket underlying{std::move(addr2), loop->Poller()};
    co_await underlying.Connect();
    TSslSocket ssl_socket(std::move(underlying), ctx);
    // if (!SSL_set_tlsext_host_name(ssl_socket.GetSsl(), url.host().c_str()))
    //     co_return WS_ERROR(TRANSPORT_ERROR, "SSL_set_tlsext_host_name failed");
    // SSL_set_verify(ssl_socket.GetSsl(), SSL_VERIFY_NONE, nullptr);
    co_await ssl_socket.Connect();

    auto socket = CoroioSocket(&logger, std::move(ssl_socket));

    // websocket client
    auto client = WebSocketClientAsync<TValueTask, decltype(logger), decltype(socket)>(
        &logger, std::move(socket)
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

    // perform handshake
    WS_CO_TRYV(co_await client.handshake(handshake, 5000ms)); // 5 sec timeout

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
    WS_CO_TRYV(co_await client.send_message(msg));

    std::chrono::time_point<std::chrono::system_clock> last_msg;
    msg_stats stats;

    Buffer buffer;
    while (true)
    {
        ++stats.counter;

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()
        )
                      .count();

        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            co_await client.read_message(buffer, 60s);

        if (auto msg = std::get_if<Message>(&var))
        {
            stats.total_bytes += msg->data.size();

            auto E = std::atoll(extract_json_property_value(msg->to_string_view(), "E").data());
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
    signal(SIGPIPE, SIG_IGN);

    Loop loop;
    auto h = client(&loop);

    while (!h.done())
    {
        loop.Step();
    }
    h.destroy();

    // auto t = std::chrono::steady_clock::now();
    // while (std::chrono::steady_clock::now() - t < std::chrono::seconds(20))
    // {
    //     loop.Step();
    // }
    // task.destroy();

    return 0;
}