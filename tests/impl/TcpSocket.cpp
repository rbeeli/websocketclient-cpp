#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "ws_client/log.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"
#include "ws_client/transport/builtin/TcpSocket.hpp"

using namespace ws_client;

TEST(TcpSocket, connect_and_wait_with_fd_above_fd_setsize)
{
    // socket fd numbers >= FD_SETSIZE overflow a select() fd_set
    rlimit original{};
    ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &original), 0);
    const rlim_t needed = FD_SETSIZE + 64;
    if (original.rlim_max != RLIM_INFINITY && original.rlim_max < needed)
        GTEST_SKIP() << "RLIMIT_NOFILE hard limit too low";
    rlimit raised = original;
    raised.rlim_cur = std::max(original.rlim_cur, needed);
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &raised), 0);

    // occupy all fd numbers below FD_SETSIZE
    std::vector<int> fillers;
    while (true)
    {
        int fd = ::open("/dev/null", O_RDONLY);
        ASSERT_GE(fd, 0);
        fillers.push_back(fd);
        if (fd >= FD_SETSIZE - 1)
            break;
    }

    // localhost listener
    int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t addr_len = sizeof(addr);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), addr_len), 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len), 0);

    {
        ConsoleLogger logger{LogLevel::N};
        DnsResolver dns(&logger);
        auto res = dns.resolve("127.0.0.1", std::to_string(ntohs(addr.sin_port)), AddrType::ipv4);
        ASSERT_TRUE(res.has_value());
        ASSERT_FALSE(res->empty());

        TcpSocket socket(&logger, std::move((*res)[0]));
        ASSERT_TRUE(socket.init().has_value());
        ASSERT_GE(socket.fd(), FD_SETSIZE);

        // waits for writability
        ASSERT_TRUE(socket.connect(std::chrono::seconds{1}).has_value());
        int peer = ::accept(listener, nullptr, nullptr);
        ASSERT_GE(peer, 0);

        // waits for readability: timeout, then data
        Timeout<> timeout{std::chrono::milliseconds{50}};
        auto readable = socket.wait_readable(timeout);
        ASSERT_TRUE(readable.has_value());
        EXPECT_FALSE(*readable);

        ASSERT_EQ(::send(peer, "x", 1, 0), 1);
        Timeout<> timeout2{std::chrono::seconds{1}};
        readable = socket.wait_readable(timeout2);
        ASSERT_TRUE(readable.has_value());
        EXPECT_TRUE(*readable);

        ::close(peer);
    }

    ::close(listener);
    for (int fd : fillers)
        ::close(fd);
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &original), 0);
}
