#define ASIO_STANDALONE 1
#define ASIO_NO_TYPEID 1

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <iostream>
#include <string>
#include <span>
#include <cstddef>
#include <expected>

#include "ws_client/errors_async.hpp"
#include "ws_client/transport/AsioSocket.hpp"

using asio::ip::tcp;
using namespace std;
using namespace ws_client;

using std::span;
using std::byte;


asio::awaitable<void> http_get_request()
{
    string host = "httpbin.org";

    auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto endpoints = co_await resolver.async_resolve(host, "http", asio::use_awaitable);
    tcp::socket socket(executor);
    co_await asio::async_connect(socket, endpoints, asio::use_awaitable);

    std::cout << "Connected to " << host << "\n";

    // send GET request
    string request = R"(GET /get HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cache-Control: max-age=0
Connection: close
Host: httpbin.org
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0)

)";
    AsioSocket asio_socket(std::move(socket));

    auto res = co_await asio_socket.write_some(span<byte>(reinterpret_cast<byte*>(request.data()), request.size()));
    if (!res.has_value())
    {
        std::cout << "Error write_some: " << res.error().message << "\n";
        co_return;
    }

    std::cout << "Sent GET request.\n";

    // read response
    char data[1024];
    auto read_res = co_await asio_socket.read_some(span<byte>(reinterpret_cast<byte*>(data), sizeof(data)));
    if (!read_res.has_value())
    {
        std::cout << "Error read_some: " << read_res.error().message << "\n";
        co_return;
    }
    string str = string(data, *read_res);
    std::cout << "Received: " << str << "\n";

    co_return;
}


int main()
{
    // https://think-async.com/Asio/asio-1.22.0/doc/asio/overview/core/concurrency_hint.html
    auto ctx = asio::io_context{ASIO_CONCURRENCY_HINT_UNSAFE_IO};
    // auto guard = asio::make_work_guard(ctx.get_executor());

    auto exception_handler = [&](auto e_ptr)
    {
        if (e_ptr)
        {
            std::rethrow_exception(e_ptr);
        }
    };

    asio::co_spawn(ctx, http_get_request, std::move(exception_handler));
    ctx.run();

    return 0;
}
