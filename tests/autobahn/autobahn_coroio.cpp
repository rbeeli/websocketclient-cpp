#include <iostream>
#include <string>
#include <format>
#include <signal.h>
#include <netinet/tcp.h>

#include "coroio/all.hpp"

#include "ws_client/ws_client_async.hpp"
#include "ws_client/transport/CoroioSocket.hpp"
#include "ws_client/PermessageDeflate.hpp"

using namespace ws_client;
using namespace NNet;
using Loop = NNet::TLoop<TDefaultPoller>;
using NNet::TValueTask;
using std::string;

[[nodiscard]] std::expected<void, WSError> check_errno(ssize_t error_code, const string& desc) noexcept
{
    if (error_code == -1)
    {
        int errno_ = errno;
        return WS_ERROR(
            uncategorized_error,
            std::format("Error during {}: {} (errno={})", desc, std::strerror(errno_), errno_),
            close_code::not_set
        );
    }
    return {};
}

template <typename TPoller>
[[nodiscard]] static TValueTask<std::expected<string, WSError>> send_request(
    string url_str, bool read_response, TPoller& poller
)
{
    WS_CO_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    TSocket tcp(TAddress{url.host(), url.port()}, poller);
    co_await tcp.Connect();

    auto socket = CoroioSocket(std::move(tcp));
    auto client = WebSocketClientAsync<TValueTask, CoroioSocket<TSocket>>(std::move(socket));
    auto handshake = Handshake(url);
    WS_CO_TRYV(co_await client.init(handshake));

    string response;
    if (read_response)
    {
        Buffer buffer;
        WS_CO_TRY(res_msg, co_await client.read_message(buffer));
        const Message& msg = *res_msg;
        response = msg.to_string();
    }

    WS_CO_TRYV(co_await client.close());

    co_return response;
}

template <typename TPoller>
[[nodiscard]] static TValueTask<std::expected<void, WSError>> run_case(string url_str, TPoller& poller)
{
    WS_CO_TRY(url_res, URL::parse(url_str));
    const URL& url = *url_res;

    // TCP socket
    TSocket tcp(TAddress{url.host(), url.port()}, poller);
    // WS_CO_TRYV(tcp.set_SO_RCVBUF(10 * 1024 * 1024)); // 10 MB
    // WS_CO_TRYV(tcp.set_SO_SNDBUF(10 * 1024 * 1024)); // 10 MB
    int flag = 1;
    int ret = setsockopt(tcp.Fd(), IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
    WS_CO_TRYV(check_errno(ret, "set TCP_NODELAY"));
    co_await tcp.Connect();

    auto socket = CoroioSocket(std::move(tcp));

    // websocket client
    auto client = WebSocketClientAsync<TValueTask, CoroioSocket<TSocket>>(std::move(socket));

    // handshake handler
    auto handshake = Handshake(url);

    // enable compression (permessage-deflate extension)
    handshake.set_permessage_deflate({
        .server_max_window_bits = 15,
        .client_max_window_bits = 15,
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .decompress_buffer_size = 100 * 1024 * 1024, // 100 MB
        .compress_buffer_size = 100 * 1024 * 1024,   // 100 MB
    });

    // start client
    WS_CO_TRYV(co_await client.init(handshake));

    Buffer buffer;
    buffer.set_max_size(100 * 1024 * 1024); // 100 MB
    while (true)
    {
        // read from server
        WS_CO_TRY(res, co_await client.read_message(buffer));
        const Message& msg = *res;

        // write message back to server
        WS_CO_TRYV(co_await client.send_message(msg));
    }

    // close client connection
    WS_CO_TRYV(co_await client.close());

    co_return {};
}

template <typename TPoller>
TValueTask<void> client(TPoller& poller)
{
    string agent = "ws_client_coroio";
    string host = "127.0.0.1:9001";
    int case_count = 0;

    // getCaseCount
    {
        auto res = co_await send_request(std::format("ws://{}/getCaseCount", host), true, poller);
        if (!res.has_value())
        {
            std::cerr << "Failed to fetch cases count: " << res.error() << std::endl;
            co_return;
        }
        auto& str = res.value();
        auto case_count_conv = std::from_chars(str.data(), str.data() + str.size(), case_count);
        if (case_count_conv.ec != std::errc{})
        {
            std::cerr << "Failed to parse number of cases: " << str << std::endl;
            co_return;
        }
    }

    // run cases
    for (int i = 1; i <= case_count; ++i)
    {
        // getCaseInfo
        {
            auto res = co_await send_request(
                std::format("ws://{}/getCaseInfo?case={}", host, i), true, poller
            );
            if (!res.has_value())
            {
                std::cerr << "Failed to fetch case info: " << res.error() << std::endl;
                co_return;
            }
            std::cout << res.value() << std::endl;
        }

        string url = std::format("ws://{}/runCase?case={}&agent={}", host, i, agent);
        auto res_case = co_await run_case(url, poller);
        if (!res_case.has_value())
            std::cerr << "Case " << i << ": " << res_case.error() << std::endl;
    }

    std::cout << "Cases processed, updating reports..." << std::endl;

    // updateReports
    {
        auto res = co_await send_request(
            std::format("ws://{}/updateReports?agent={}", host, agent), false, poller
        );
        if (!res.has_value())
        {
            std::cerr << "Failed to update reports: " << res.error() << std::endl;
            co_return;
        }
    }

    std::cout << "Autobahn test cases finished." << std::endl;

    co_return;
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    Loop loop;
    auto task = client(loop.Poller());

    do
    {
        loop.Step();
    } while (!task.done());

    task.destroy();

    return 0;
};