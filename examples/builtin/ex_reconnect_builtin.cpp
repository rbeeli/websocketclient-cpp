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

expected<void, WSError> run()
{
    // parse URL
    WS_TRY(url, URL::parse("wss://fstream.binance.com/ws"));

    // websocketclient logger
    ConsoleLogger logger{LogLevel::D};
    logger.set_level(LogTopic::DNS, LogLevel::D);
    logger.set_level(LogTopic::TCP, LogLevel::D);
    logger.set_level(LogTopic::Handshake, LogLevel::D);

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

    // // we don't subscribe so it looks like we are not receiving any messages
    // std::string sub_msg = R"({
    //     "method": "SUBSCRIBE",
    //     "params": ["btcusdt@aggTrade"],
    //     "id": 1
    // })";
    // Message msg(MessageType::text, sub_msg);
    // WS_TRYV(client.send_message(msg, {.compress = false}));

    // allocate message buffer with 4 KiB initial size and 1 MiB max size
    WS_TRY(buffer, Buffer::create(4096, 1 * 1024 * 1024));

    while (true)
    {
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(*buffer, 5s);                              // 5 sec timeout

        if (auto msg = std::get_if<Message>(&var))
        {
            std::cout << msg->to_string() << std::endl;
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
            if (err->code == WSErrorCode::timeout_error)
            {
                std::cout << "read_message timed out\n";
                break;
            }

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
    // loop to restart the client after an error
    while (true)
    {
        auto res = run();
        if (!res.has_value())
        {
            std::cerr << "Error: " << res.error() << std::endl;
        }
    }
    return 0;
};