#include <iostream>
#include <string>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <thread>

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#define WS_CLIENT_LOG_MSG_SIZES 1
#define WS_CLIENT_LOG_FRAMES 1
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"
#include <signal.h>

using namespace ws_client;

expected<void, WSError> run()
{
    WS_TRY(url_res, URL::parse("wss://localhost:9443"));
    URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::D> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str(), AddrType::IPv4));
    AddressInfo& addr = (*dns_res)[0];

    // create socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.connect());

    // SSL socket wrapper
    OpenSslContext ctx(&logger);
    WS_TRYV(ctx.init());
    WS_TRYV(ctx.set_default_verify_paths());
    WS_TRYV(ctx.load_verify_file("cert.pem"));
    WS_TRYV(ctx.set_session_cache_mode_client());
    auto ssl = OpenSslSocket(&logger, tcp.get_fd(), &ctx, url.host(), true);
    WS_TRYV(ssl.init());
    WS_TRYV(ssl.connect());

    // create websocket client
    auto client = WebSocketClient(&logger, std::move(ssl));
    
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

    // start client
    WS_TRYV(client.init(handshake));

    // send message
    string payload = "test";
    Message msg(MessageType::TEXT, payload);
    WS_TRYV(client.send_message(msg));
    
    Buffer buffer;
    while (true)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(buffer);

        if (auto msg = std::get_if<Message>(&var))
        {
            WS_TRYV(client.send_message(*msg));
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

    // wait for server to close connection
    std::this_thread::sleep_for(std::chrono::seconds(1));

    WS_TRYV(client.close(close_code::NORMAL_CLOSURE));

    return {};
};


int main()
{
    // ignore SIGPIPE (Broken pipe) signal (causes process to terminate)
    signal(SIGPIPE, SIG_IGN);
    
    auto res = run();
    if (!res.has_value())
    {
        std::cerr << "Error: " << res.error().message << std::endl;
        return 2;
    }
    return 0;
};