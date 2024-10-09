#include <iostream>
#include <string>
#include <format>
#include <variant>
#include <expected>
#include <thread>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

using namespace ws_client;

expected<void, WSError> run()
{
    // parse URL
    WS_TRY(url, URL::parse("wss://echo.websocket.org/"));

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

    // custom HTTP header
    handshake.get_request_header().fields.set("X-Custom-Header", "Custom-Value");

    // perform handshake
    WS_TRYV(client.handshake(handshake, 5s)); // 5 sec timeout

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    for (int i = 0;; i++)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(*buffer, 5s);                             // 5 sec timeout

        if (std::get_if<Message>(&var))
        {
            // write message back to server
            string text = std::format("This is the {}th message", i);
            Message msg2(MessageType::text, text);
            WS_TRYV(client.send_message(msg2));
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
            logger.log<LogLevel::E, LogTopic::User>(std::format("Error: {}", err->message));
            WS_TRYV(client.close(err->close_with_code));
            return {};
        }
    }

    WS_TRYV(client.close(close_code::normal_closure));

    return {};
};


int main()
{
    // run loop, reconnects on error
    while (true)
    {
        auto res = run();
        if (!res.has_value())
        {
            std::cerr << "Error: " << res.error() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::clog << "Reconnecting..." << std::endl;
        }
    }

    return 0;
};