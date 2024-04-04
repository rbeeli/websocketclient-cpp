#include <iostream>
#include <signal.h>
#include <string>
#include <chrono>

#include "coroio/all.hpp"

#define WS_CLIENT_VALIDATE_UTF8 1

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#define WS_CLIENT_LOG_MSG_SIZES 1
#define WS_CLIENT_LOG_FRAMES 1
#define WS_CLIENT_LOG_PING_PONG 1

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/CoroioSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"
#include "ws_client/WebSocketClientAsync.hpp"
#include "ws_client/ws_client.hpp"

using namespace ws_client;
using namespace NNet;
using Loop = NNet::TLoop<NNet::TEPoll>;

TValueTask<expected<void, WSError>> client(Loop* loop)
{
    WS_CO_TRY(url_res, URL::parse("wss://fstream.binance.com/ws"));
    URL& url = *url_res;

    // resolve hostname
    WS_CO_TRY(dns_res, DnsResolver::resolve(url.host(), url.port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // TAddress address(&addr.address.addr, addr.ai_addrlen);
    // TAddress addr2(addr.address.addr, addr.ai_addrlen);
    TAddress addr2{addr.ip, addr.port()};
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

    auto socket = CoroioSocket(std::move(ssl_socket));

    // websocket client
    auto client = WebSocketClientAsync<TValueTask, CoroioSocket<TSslSocket<TSocket>>>(socket);

    // handshake handler
    auto handshake = Handshake(url);

    // start client
    WS_CO_TRY(res, co_await client.init(handshake));

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
    Message msg = Message::from_string(std::move(sub_msg), MessageType::TEXT);
    WS_CO_TRYV(co_await client.send_message(msg));

    Buffer buffer;
    while (true)
    {
        WS_CO_TRY(res2, co_await client.read_message(buffer));
        Message& msg = *res2;
        // // Message msg = Message::from_string("", MessageType::TEXT);
        // auto res3 = co_await client.send_message(msg);
        // if (!res3.has_value())
        // {
        //     std::cerr << "Error: " << res3.error().message << std::endl;
        //     continue;
        // }

        std::cout << msg.to_string() << std::endl;

        buffer.clear();
    }

    WS_CO_TRYV(co_await client.close());

    co_return {};
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    Loop loop;
    auto h = client(&loop);
    
    while (!h.done()) {
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