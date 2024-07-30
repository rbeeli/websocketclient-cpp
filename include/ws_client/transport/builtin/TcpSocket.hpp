#pragma once

#include <expected>
#include <span>
#include <chrono>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/utils/networking.hpp"
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/transport/ISocket.hpp"
#include "ws_client/transport/builtin/DnsResolver.hpp"

namespace ws_client
{
using std::string;
using std::byte;
using namespace std::chrono_literals;

/**
 * A blocking TCP socket implementation.
 * The socket is closed when the object is destroyed.
 */
template <typename TLogger>
class TcpSocket final : public ISocket
{
private:
    TLogger* logger_;
    int fd_ = -1;
    AddressInfo address_;
    bool connected_ = false;

public:
    /**
     * Create a TCP socket from a hostname and a port.
     * The socket will be closed when the object is destroyed.
     * @param address       The address info of the server to connect to.
     */
    explicit TcpSocket(TLogger* logger, AddressInfo address) noexcept
        : ISocket(), logger_(logger), address_(std::move(address))
    {
    }

    ~TcpSocket() noexcept override
    {
        if (fd_ != -1)
            this->close();
    }

    // disable copy
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    // enable move
    TcpSocket(TcpSocket&& other) noexcept
        : logger_(other.logger_),
          fd_(other.fd_),
          address_(std::move(other.address_)),
          connected_(other.connected_)
    {
        other.fd_ = -1;
    }
    TcpSocket& operator=(TcpSocket&& other) noexcept
    {
        if (this != &other)
        {
            if (fd_ != -1)
                this->close();
            logger_ = other.logger_;
            fd_ = other.fd_;
            address_ = std::move(other.address_);
            connected_ = other.connected_;
            other.fd_ = -1;
        }
        return *this;
    }

    /**
     * Get the file descriptor of the socket.
     */
    [[nodiscard]] int get_fd() const noexcept
    {
        return fd_;
    }

    /**
     * Initialize the socket and set options.
     * This function must be called before `connect`.
     */
    [[nodiscard]] expected<void, WSError> init()
    {
        // create a socket based on family (IPv4 or IPv6)
        logger_->template log<LogLevel::D>(
            "Creating socket (family=" + std::to_string(address_.family()) + ")"
        );
        fd_ = ::socket(address_.family(), SOCK_STREAM, 0);
        if (fd_ == -1)
        {
            int error_code = errno;
            return WS_ERROR(
                TRANSPORT_ERROR,
                "Error creating TCP socket: " + std::string(std::strerror(error_code)) + " (" +
                    std::to_string(error_code) + ")",
                NOT_SET
            );
        }

        // set non-blocking mode by default
        WS_TRYV(this->set_O_NONBLOCK(true));

        // disable Nagle's algorithm by default
        WS_TRYV(this->set_TCP_NODELAY(true));

        // enable quickack by default (if available on platform)
        WS_TRYV(this->set_TCP_QUICKACK(true));

        logger_->template log<LogLevel::D>("Socket created (fd=" + std::to_string(fd_) + ")");

        return {};
    }

    /**
     * Establish a connection to the server.
     */
    [[nodiscard]] expected<void, WSError> connect(std::chrono::milliseconds timeout_ms = 5000ms)
    {
        if (connected_)
        {
            logger_->template log<LogLevel::D>("Connection already established");
            return {};
        }

        if (fd_ == -1)
            return WS_ERROR(LOGIC_ERROR, "Socket not created. Call init() first.", NOT_SET);

        Timeout timeout(timeout_ms);

        // attempt to connect
        int ret = ::connect(fd_, address_.sockaddr_ptr(), address_.addrlen());
        if (ret == 0)
        {
            connected_ = true;
            return {};
        }

        // check if connection is in progress due to non-blocking mode
        if (errno != EINPROGRESS)
            return this->check_errno(-1, "connecting to the server");

        // use select to wait for the connection or timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd_, &write_fds);

        // wait for data to read or timeout
        int select_ret;
        do
        {
            auto remaining = timeout.remaining_timeval();
            select_ret = ::select(fd_ + 1, nullptr, &write_fds, nullptr, &remaining);
        } while (select_ret == -1 && errno == EINTR);

        if (select_ret == 0) [[unlikely]]
            return WS_ERROR(TIMEOUT, "Connect timeout", NOT_SET);

        WS_TRYV(this->check_errno(select_ret, "connect"));

        // check if the connection was successful
        int error;
        socklen_t len = sizeof(error);
        ret = getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len);
        WS_TRYV(this->check_errno(ret, "getsockopt"));
        if (error != 0)
        {
            std::string error_message = std::strerror(error);
            std::stringstream ss;
            ss << "Connect failed to " << address_.hostname() << ":" << address_.port()
               << " (" << address_.ip() << "): " << error_message << " (error code: " << error
               << ")";
            return WS_ERROR(TRANSPORT_ERROR, ss.str(), NOT_SET);
        }

        connected_ = true;

        if (logger_->template is_enabled<LogLevel::I>())
        {
            auto elapsed = timeout.template elapsed<std::chrono::microseconds>();
            std::stringstream ss;
            ss << "Connected to " << address_.hostname() << ":" << address_.port() << " ("
               << address_.ip() << ") in " << elapsed.count() << " µs";
            logger_->template log<LogLevel::I>(ss.str());
        }

        return {};
    }

    /**
     * Enable or disable TCP_NODELAY option (Nagle's algorithm).
     * Disabling Nagle's algorithm can reduce latency due to reduced buffering.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_NODELAY(bool value)
    {
        int flag = value ? 1 : 0;
        int ret = setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_errno(ret, "set TCP_NODELAY"));
        logger_->template log<LogLevel::D>("TCP_NODELAY=" + std::to_string(value));
        return {};
    }

    /**
     * Enable or disable O_NONBLOCK option (non-blocking mode).
     */
    [[nodiscard]] expected<void, WSError> set_O_NONBLOCK(bool value)
    {
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags == -1)
            return WS_ERROR(TRANSPORT_ERROR, "Failed to get socket flags", NOT_SET);

        if (value)
            flags |= O_NONBLOCK;
        else
            flags &= ~O_NONBLOCK;

        if (fcntl(fd_, F_SETFL, flags) == -1)
            return WS_ERROR(TRANSPORT_ERROR, "Failed to set socket to non-blocking", NOT_SET);

        logger_->template log<LogLevel::D>("O_NONBLOCK=" + std::to_string(value));
        return {};
    }

    /**
     * Set SO_RCVBUF option (receive buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_RCVBUF(int buffer_size)
    {
        int ret = setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_errno(ret, "set SO_RCVBUF"));
        logger_->template log<LogLevel::D>(
            "socket receive buffer size SO_RCVBUF=" + std::to_string(buffer_size)
        );
        return {};
    }

    /**
     * Set SO_SNDBUF option (send buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_SNDBUF(int buffer_size)
    {
        int ret = setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_errno(ret, "set SO_SNDBUF"));
        logger_->template log<LogLevel::D>(
            "socket send buffer size SO_SNDBUF=" + std::to_string(buffer_size)
        );
        return {};
    }

    /**
     * Enable or disable TCP_QUICKACK option.
     * Enabling TCP_QUICKACK can reduce latency by disabling delayed ACKs.
     * 
     * Note: TCP_QUICKACK is not available on macOS, hence a no-op on that platform.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_QUICKACK(bool value)
    {
        (void)value; // suppress unused parameter warning
#ifdef TCP_QUICKACK
        int flag = value ? 1 : 0;
        int ret = setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_errno(ret, "set TCP_QUICKACK"));
        logger_->template log<LogLevel::D>("TCP_QUICKACK=" + std::to_string(value));
#endif
        return {};
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * 
     * @return The number of bytes read, or an error.
     */
    [[nodiscard]] inline expected<size_t, WSError> read_some(
        span<byte> buffer, Timeout<>& timeout
    ) noexcept override
    {
        // create fd_set for select with timeout
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd_, &read_fds);

        ssize_t ret = 0;
        do
        {
            // wait for data to read or timeout
            int select_ret;
            do
            {
                auto remaining = timeout.remaining_timeval();
                select_ret = ::select(fd_ + 1, &read_fds, nullptr, nullptr, &remaining);
            } while (select_ret == -1 && errno == EINTR);

            if (select_ret == 0) [[unlikely]]
                return WS_ERROR(TIMEOUT, "Read timeout", NOT_SET);

            WS_TRYV(this->check_errno(select_ret, "read_some (select)"));

            // read data from socket using `recv`, retry on EINTR
            do
            {
                constexpr int flags = MSG_NOSIGNAL; // prevent SIGPIPE signal on broken pipe
                ret = ::recv(fd_, buffer.data(), buffer.size(), flags);
            } while (ret == -1 && errno == EINTR);

            if (ret == 0) [[unlikely]]
                return WS_ERROR(TRANSPORT_ERROR, "Connection closed on transport layer", NOT_SET);

            // retry on EAGAIN or EWOULDBLOCK (non-blocking), should not happen with select normally
        } while (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));

        WS_TRYV(this->check_errno(ret, "read_some"));

        return static_cast<size_t>(ret);
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * 
     * @return The number of bytes written, or an error.
     */
    [[nodiscard]] inline expected<size_t, WSError> write_some(
        const span<byte> buffer, Timeout<>& timeout
    ) noexcept override
    {
        // create fd_set for select with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd_, &write_fds);

        ssize_t ret = 0;
        do
        {
            // wait for socket to be ready for writing or timeout
            int select_ret;
            do
            {
                auto remaining = timeout.remaining_timeval();
                select_ret = ::select(fd_ + 1, nullptr, &write_fds, nullptr, &remaining);
            } while (select_ret == -1 && errno == EINTR);

            if (select_ret == 0) [[unlikely]]
                return WS_ERROR(TIMEOUT, "Write timeout", NOT_SET);

            WS_TRYV(this->check_errno(select_ret, "write_some (select)"));

            // write data to socket using `send`, retry on EINTR
            do
            {
                constexpr int flags = MSG_NOSIGNAL; // prevent SIGPIPE signal on broken pipe
                ret = ::send(fd_, buffer.data(), buffer.size(), flags);
            } while (ret == -1 && errno == EINTR);

            if (ret == 0) [[unlikely]]
                return WS_ERROR(TRANSPORT_ERROR, "Connection closed on transport layer", NOT_SET);

            // retry on EAGAIN or EWOULDBLOCK (non-blocking), should not happen with select normally
        } while (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));

        WS_TRYV(this->check_errno(ret, "write_some"));

        return static_cast<size_t>(ret);
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> shutdown(Timeout<>& timeout) noexcept override
    {
        if (fd_ != -1)
        {
            logger_->template log<LogLevel::D>(
                "Shutting down socket (fd=" + std::to_string(fd_) + ")"
            );
            int ret = ::shutdown(fd_, SHUT_RDWR);
            if (ret != 0)
            {
                auto err = this->check_errno(ret, "Shut down of socket failed");
                logger_->template log<LogLevel::W>(err.error().message);
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
        if (fd_ != -1)
        {
            logger_->template log<LogLevel::D>(
                "Closing socket (fd=" + std::to_string(fd_) + ")"
            );
            int ret = ::close(fd_);
            if (ret != 0)
            {
                auto err = this->check_errno(ret, "Socket close failed");
                logger_->template log<LogLevel::W>(err.error().message);
                return err;
            }
            fd_ = -1;
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