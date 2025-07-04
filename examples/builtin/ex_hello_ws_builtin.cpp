// NOTE: Must run Python 3 script `run_ws_server.py` before running this example.

// This example demonstrates how to create a WebSocket client using the ws_client library.
// It uses a bare, unencrypted TCP socket to connect to a WebSocket server running on localhost:8080.
// Read and write timeouts are set to 1000 ms directly on the POSIX socket (see set_recv_timeout, set_send_timeout).

#include <iostream>
#include <string>
#include <format>
#include <chrono>
#include <algorithm>
#include <iomanip>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace std::chrono_literals;

std::expected<void, WSError> run()
{
    WS_TRY(url, URL::parse("wss://localhost:8080"));

    // websocketclient logger
    ConsoleLogger logger{LogLevel::D};
    logger.set_level(LogTopic::DNS, LogLevel::D);
    logger.set_level(LogTopic::TCP, LogLevel::D);
    logger.set_level(LogTopic::Handshake, LogLevel::D);
    logger.set_level(LogTopic::RecvFrame, LogLevel::D);
    logger.set_level(LogTopic::RecvFramePayload, LogLevel::D);
    logger.set_level(LogTopic::SendFrame, LogLevel::D);
    logger.set_level(LogTopic::SendFramePayload, LogLevel::D);

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url->host(), url->port_str(), AddrType::ipv4));
    AddressInfo& addr = (*dns_res)[0];

    // create TCP socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.connect(2s)); // 2 sec connect timeout

    // create websocket client
    auto client = WebSocketClient(&logger, std::move(tcp));

    // handshake handler
    auto handshake = Handshake(&logger, *url);

    // enable compression (permessage-deflate extension)
    handshake.set_permessage_deflate(
        {.logger = &logger,
         .server_max_window_bits = 15,
         .client_max_window_bits = 15,
         .server_no_context_takeover = true,
         .client_no_context_takeover = true}
    );

    // perform handshake
    WS_TRYV(client.handshake(handshake, 5s)); // 5 sec timeout

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (true)
    {
        // read message from server into buffer
        std::variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(*buffer, 30s);                                 // 30 sec timeout

        if (auto msg = std::get_if<Message>(&var))
        {
            WS_TRYV(client.send_message(*msg, {.timeout = 5s})); // 5 sec timeout
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

    WS_TRYV(client.close(close_code::normal_closure));

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
