// NOTE: Must run Python 3 script `run_ws_server.py` before running this example.

// This example demonstrates how to create a WebSocket client using the ws_client library.
// It uses a bare, unencrypted TCP socket to connect to a WebSocket server running on localhost:8080.
// Read and write timeouts are set to 1000 ms directly on the POSIX socket (see set_recv_timeout, set_send_timeout).

#include <iostream>
#include <string>
#include <chrono>
#include <algorithm>
#include <iomanip>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono_literals;

expected<void, WSError> run()
{
    WS_TRY(url_res, URL::parse("wss://localhost:8080"));
    URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str(), AddrType::IPv4));
    AddressInfo& addr = (*dns_res)[0];

    // create TCP socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.connect(2000ms)); // 2 sec connect timeout

    // create websocket client
    auto client = WebSocketClient(&logger, std::move(tcp));
    
    // handshake handler
    auto handshake = Handshake(&logger, url);

    // enable compression (permessage-deflate extension)
    handshake.set_permessage_deflate({
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true
    });

    // perform handshake
    WS_TRYV(client.handshake(handshake, 5000ms)); // 5 sec timeout

    Buffer buffer;
    while (true)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(buffer, 30'000ms); // 30 sec timeout

        if (auto msg = std::get_if<Message>(&var))
        {
            WS_TRYV(client.send_message(*msg, {.timeout = 5000ms})); // 5 sec timeout
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            logger.log<LogLevel::D>("Ping frame received");
            WS_TRYV(client.send_pong_frame(ping_frame->payload_bytes()));
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
            WS_TRYV(client.close(err->close_with_code));
            return {};
        }
    }

    WS_TRYV(client.close(close_code::NORMAL_CLOSURE));

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
