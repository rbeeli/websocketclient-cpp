#include <iostream>
#include <string>
#include <variant>

#define WS_CLIENT_LOG_HANDSHAKE 0
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#define WS_CLIENT_LOG_MSG_SIZES 0
#define WS_CLIENT_LOG_FRAMES 0

#include "ws_client/ws_client.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using std::string;
using std::variant;
using std::span;
using std::byte;

[[nodiscard]] static expected<string, WSError> send_request(string url_str, bool read_response)
{
    WS_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::E> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // create socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.connect());

    auto client = WebSocketClient(&logger, std::move(tcp));
    auto handshake = Handshake(&logger, url);

    WS_TRYV(client.init(handshake));

    string response;
    if (read_response)
    {
        Buffer buffer;

        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(buffer);

        if (auto msg = std::get_if<Message>(&var))
        {
            response = msg->to_string();
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            WS_TRYV(client.send_pong_frame(ping_frame->payload_bytes()));
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            std::cerr << "Error: " << err->message << std::endl;
        }
        else
            throw std::runtime_error("Unexpected message type");
    }

    WS_TRYV(client.close(close_code::NORMAL_CLOSURE));

    return response;
}

[[nodiscard]] static expected<void, WSError> run_case(string url_str)
{
    WS_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    // websocketclient logger
    ConsoleLogger<LogLevel::E> logger;

    // resolve hostname
    DnsResolver dns(&logger);
    WS_TRY(dns_res, dns.resolve(url.host(), url.port_str()));
    AddressInfo& addr = (*dns_res)[0];

    // create socket
    auto tcp = TcpSocket(&logger, std::move(addr));
    WS_TRYV(tcp.init());
    WS_TRYV(tcp.set_SO_RCVBUF(10 * 1024 * 1024)); // 10 MB
    WS_TRYV(tcp.set_SO_SNDBUF(10 * 1024 * 1024)); // 10 MB
    WS_TRYV(tcp.connect());

    // websocket client
    auto client = WebSocketClient(&logger, std::move(tcp));

    // handshake handler
    auto handshake = Handshake(&logger, url);
    handshake.set_timeout(std::chrono::seconds(5));

    // enable compression (permessage-deflate extension)
    handshake.set_permessage_deflate({
        .logger = &logger,
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    });

    // start client
    WS_TRYV(client.init(handshake));

    Buffer buffer;
    buffer.set_max_size(100 * 1024 * 1024); // 100 MB
    while (true)
    {
        // read message from server into buffer
        variant<Message, PingFrame, PongFrame, CloseFrame, WSError> var = //
            client.read_message(buffer);

        if (auto msg = std::get_if<Message>(&var))
        {
            // write message back to server
            WS_TRYV(client.send_message(*msg));
        }
        else if (auto ping_frame = std::get_if<PingFrame>(&var))
        {
            WS_TRYV(client.send_pong_frame(ping_frame->payload_bytes()));
        }
        else if (std::holds_alternative<PongFrame>(var))
        {
        }
        else if (std::holds_alternative<CloseFrame>(var))
        {
            break;
        }
        else if (auto err = std::get_if<WSError>(&var))
        {
            std::cerr << "Error: " << err->message << std::endl;
            WS_TRYV(client.close(err->close_with_code));
            break;
        }
        else
            throw std::runtime_error("Unexpected message type");
    }

    WS_TRYV(client.close(close_code::NORMAL_CLOSURE));

    return {};
}

int main()
{
    string agent = WS_AUTOBAHN_AGENT_NAME;
    string host = "127.0.0.1:9001";
    int case_count = 0;

    // getCaseCount
    {
        auto res = send_request("ws://" + host + "/getCaseCount", true);
        if (!res.has_value())
        {
            std::cerr << "Failed to fetch cases count: " << res.error() << std::endl;
            return 1;
        }
        auto& str = res.value();
        auto case_count_conv = std::from_chars(str.data(), str.data() + str.size(), case_count);
        if (case_count_conv.ec != std::errc{})
        {
            std::cerr << "Failed to parse number of cases: " << str << std::endl;
            return 1;
        }
    }

    // run cases
    for (int i = 1; i <= case_count; ++i)
    {
        // getCaseInfo
        {
            auto res = send_request(
                "ws://" + host + "/getCaseInfo?case=" + std::to_string(i), true
            );
            if (!res.has_value())
            {
                std::cerr << "Failed to fetch case info: " << res.error() << std::endl;
                return 1;
            }
            std::cout << res.value() << std::endl;
        }

        string url = "ws://" + host + "/runCase?case=" + std::to_string(i) + "&agent=" + agent;
        auto res_case = run_case(url);
        if (!res_case.has_value())
            std::cerr << "Case " << i << ": " << res_case.error() << std::endl;
    }

    std::cout << "Cases processed, updating reports..." << std::endl;

    // updateReports
    {
        auto res = send_request("ws://" + host + "/updateReports?agent=" + agent, false);
        if (!res.has_value())
        {
            std::cerr << "Failed to update reports: " << res.error() << std::endl;
            return 1;
        }
    }

    std::cout << "Autobahn test cases finished." << std::endl;

    return 0;
};