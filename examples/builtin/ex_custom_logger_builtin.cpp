#include <iostream>
#include <string>
#include <variant>
#include <expected>
#include <thread>
#include <chrono>
#include <source_location>

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

using namespace ws_client;
using namespace std::chrono_literals;

/**
 * Custom logger implementation.
 * Logs all messages to `std::cout`.
 */
struct CustomLogger
{
    /**
     * Check if the logger is enabled for the given log level.
     */
    template <LogLevel level>
    constexpr bool is_enabled() const noexcept
    {
        return true;
    }

    /**
     * Log a message with the given log level.
     */
    template <LogLevel level>
    constexpr void log(
        std::string_view message, const std::source_location loc = std::source_location::current()
    ) noexcept
    {
        std::cout << "CustomLogger: " << loc.file_name() << ":" << loc.line() << " " << message
                  << std::endl;
    }
};


expected<void, WSError> run()
{
    // parse URL
    WS_TRY(url_res, URL::parse("wss://echo.websocket.org/"));
    URL& url = *url_res;

    // custom logger
    CustomLogger logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str(), AddrType::IPv4));
    AddressInfo& addr = (*dns_res)[0];

    // create TCP socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());

    // SSL socket wrapper
    OpenSslContext ctx(&logger);
    WS_TRYV(ctx.init());
    WS_TRYV(ctx.set_default_verify_paths());
    auto ssl = OpenSslSocket(&logger, std::move(tcp), &ctx, url.host(), true);
    WS_TRYV(ssl.init());
    WS_TRYV(ssl.connect(2000ms)); // 2 sec connect timeout

    // websocket client
    auto client = WebSocketClient(&logger, std::move(ssl));

    // handshake handler
    auto handshake = Handshake(&logger, url);

    // perform handshake
    WS_TRYV(client.handshake(handshake, 5000ms)); // 5 sec timeout

    Buffer buffer;
    for (int i = 0;; i++)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(buffer, 60s); // 60 sec timeout

        if (std::get_if<Message>(&var))
        {
            // write message back to server
            string text = "This is the " + std::to_string(i) + "th message";
            Message msg2(MessageType::text, text);
            WS_TRYV(client.send_message(msg2));
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
            std::cerr << "Error: " << res.error().message << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::clog << "Reconnecting..." << std::endl;
        }
    }

    return 0;
};