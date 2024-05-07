#pragma once

#include <expected>
#include <span>
#include <chrono>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/networking.hpp"
#include "ws_client/transport/ISocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

namespace ws_client
{
using std::string;
using std::byte;

/**
 * A blocking TCP socket implementation.
 * The socket is closed when the object is destroyed.
 */
template <typename TLogger>
class TcpSocket final : public ISocket
{
private:
    TLogger* logger;
    int fd = -1;
    AddressInfo address;
    bool connected = false;

public:
    /**
     * Create a TCP socket from a hostname and a port.
     * The socket will be closed when the object is destroyed.
     * @param address       The address info of the server to connect to.
     */
    explicit TcpSocket(TLogger* logger, AddressInfo address) noexcept
        : ISocket(), logger(logger), address(std::move(address))
    {
    }

    ~TcpSocket() noexcept override
    {
        if (this->fd != -1)
        {
            this->close();
        }
        this->logger = nullptr;
    }

    // disable copy
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    // enable move
    TcpSocket(TcpSocket&& other) noexcept
        : logger(other.logger), fd(other.fd), address(std::move(other.address))
    {
        other.fd = -1;
    }
    TcpSocket& operator=(TcpSocket&& other) noexcept
    {
        if (this != &other)
        {
            if (this->fd != -1)
                this->close();
            this->logger = other.logger;
            this->fd = other.fd;
            this->address = std::move(other.address);
            other.fd = -1;
        }
        return *this;
    }

    [[nodiscard]] int get_fd() const noexcept
    {
        return fd;
    }

    [[nodiscard]] expected<void, WSError> init()
    {
        // create a socket based on family (IPv4 or IPv6)
        logger->template log<LogLevel::D>(
            "Creating socket (family=" + std::to_string(this->address.family()) + ")"
        );
        this->fd = ::socket(this->address.family(), SOCK_STREAM, 0);
        if (this->fd == -1)
        {
            int error_code = errno;
            return WS_ERROR(
                TRANSPORT_ERROR,
                "Error creating TCP socket: " + std::string(std::strerror(error_code)) + " (" +
                    std::to_string(error_code) + ")",
                NOT_SET
            );
        }

        logger->template log<LogLevel::D>("Socket created (fd=" + std::to_string(this->fd) + ")");

        // disable Nagle's algorithm by default
        WS_TRYV(this->set_TCP_NODELAY(true));

        // enable quickack by default (if available on platform)
        WS_TRYV(this->set_TCP_QUICKACK(true));

        return {};
    }

    [[nodiscard]] expected<void, WSError> connect()
    {
        if (connected)
            return {};

        if (this->fd == -1)
            return WS_ERROR(TRANSPORT_ERROR, "Socket not created. Call init() first.", NOT_SET);

        auto now = std::chrono::system_clock::now();

        // connect using sockaddr from addrinfo
        int ret = ::connect(this->fd, this->address.sockaddr_ptr(), this->address.addrlen());
        WS_TRYV(this->check_errno(ret, "connecting to the server"));

        if (logger->template is_enabled<LogLevel::I>())
        {
            std::stringstream ss;
            ss << "Connected to " << this->address.hostname() << ":" << this->address.port() << " ("
               << this->address.ip() << ") in "
               << std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::system_clock::now() - now
                  )
                      .count()
               << " µs";
            logger->template log<LogLevel::I>(ss.str());
        }

        connected = true;

        return {};
    }

    /**
     * Enable or disable TCP_NODELAY option (Nagle's algorithm).
     * Disabling Nagle's algorithm can reduce latency due to reduced buffering.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_NODELAY(bool value)
    {
        int flag = value ? 1 : 0;
        int ret = setsockopt(this->fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_errno(ret, "set TCP_NODELAY"));
        logger->template log<LogLevel::D>("TCP_NODELAY=" + std::to_string(value));
        return {};
    }

    /**
     * Set SO_RCVBUF option (receive buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_RCVBUF(int buffer_size)
    {
        int ret = setsockopt(this->fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_errno(ret, "set SO_RCVBUF"));
        logger->template log<LogLevel::D>(
            "socket receive buffer size SO_RCVBUF=" + std::to_string(buffer_size)
        );
        return {};
    }

    /**
     * Set SO_SNDBUF option (send buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_SNDBUF(int buffer_size)
    {
        int ret = setsockopt(this->fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_errno(ret, "set SO_SNDBUF"));
        logger->template log<LogLevel::D>(
            "socket send buffer size SO_SNDBUF=" + std::to_string(buffer_size)
        );
        return {};
    }

    /**
     * Enable or disable TCP_QUICKACK option.
     * Enabling TCP_QUICKACK can reduce latency by disabling delayed ACKs.
     * Note: TCP_QUICKACK is not available on macOS, hence a no-op on that platform.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_QUICKACK(bool value)
    {
        (void)value; // suppress unused parameter warning
#ifdef TCP_QUICKACK
        int flag = value ? 1 : 0;
        int ret = setsockopt(this->fd, IPPROTO_TCP, TCP_QUICKACK, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_errno(ret, "set TCP_QUICKACK"));
        logger->template log<LogLevel::D>("TCP_QUICKACK=" + std::to_string(value));
#endif
        return {};
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline expected<size_t, WSError> read_some(span<byte> buffer) noexcept override
    {
        ssize_t ret = 0;
        do
        {
            constexpr int flags = 0;
            ret = ::recv(this->fd, buffer.data(), buffer.size(), flags);
        } while (ret == -1 && errno == EINTR);

        if (ret == 0)
            return WS_ERROR(TRANSPORT_ERROR, "Connection closed on transport layer", NOT_SET);

        WS_TRYV(this->check_errno(ret, "read"));

        return static_cast<size_t>(ret);
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] inline expected<size_t, WSError> write_some( //
        const span<byte> buffer
    ) noexcept override
    {
        ssize_t ret = 0;
        do
        {
            constexpr int flags = MSG_NOSIGNAL; // prevent SIGPIPE signal on broken pipe
            ret = ::send(this->fd, buffer.data(), buffer.size(), flags);
        } while (ret == -1 && errno == EINTR);

        if (ret == 0)
            return WS_ERROR(TRANSPORT_ERROR, "Connection closed on transport layer", NOT_SET);

        WS_TRYV(this->check_errno(ret, "write"));

        return static_cast<size_t>(ret);
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket
     * for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> shutdown() noexcept override
    {
        if (this->fd != -1)
        {
            logger->template log<LogLevel::D>(
                "Shutting down socket (fd=" + std::to_string(this->fd) + ")"
            );
            int ret = ::shutdown(this->fd, SHUT_RDWR);
            if (ret != 0)
            {
                auto err = this->check_errno(ret, "Shut down of socket failed");
                logger->template log<LogLevel::W>(err.error().message);
                return err;
            }
        }
        return {};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> close() noexcept override
    {
        if (this->fd != -1)
        {
            logger->template log<LogLevel::D>(
                "Closing socket (fd=" + std::to_string(this->fd) + ")"
            );
            int ret = ::close(this->fd);
            if (ret != 0)
            {
                auto err = this->check_errno(ret, "Socket close failed");
                logger->template log<LogLevel::W>(err.error().message);
                return err;
            }
            this->fd = -1;
        }
        return {};
    }

private:
    [[nodiscard]] expected<void, WSError> check_errno(
        ssize_t error_code, const string& desc
    ) noexcept
    {
        if (error_code != -1)
            return {};

        int errno_ = errno;
        return WS_ERROR(
            TRANSPORT_ERROR,
            "Error during " + desc + ": " + string(std::strerror(errno_)) + " (" +
                std::to_string(errno_) + ")",
            NOT_SET
        );
    }
};

} // namespace ws_client