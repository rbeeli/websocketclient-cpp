#include <iostream>
#include <string>
#include <thread>
#include <source_location>

#define WS_CLIENT_LOG_HANDSHAKE 1
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#define WS_CLIENT_LOG_MSG_SIZES 1
#define WS_CLIENT_LOG_FRAMES 1
#define WS_CLIENT_LOG_PING_PONG 1
#define WS_CLIENT_LOG_COMPRESSION 0

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/OpenSslSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

using namespace ws_client;

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

    // create socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
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

    // start client
    WS_TRYV(client.init(handshake));

    Buffer buffer;
    for (int i = 0;; i++)
    {
        // automatically clear buffer on every iteration
        BufferClearGuard guard(buffer);

        // read message from server into buffer
        WS_TRY(res_msg, client.read_message(buffer));

        // write back to server
        string text = "This is the " + std::to_string(i) + "th message";
        Message msg2(MessageType::TEXT, text);
        WS_TRYV(client.send_message(msg2));
    }

    WS_TRYV(client.close());

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