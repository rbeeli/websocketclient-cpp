#pragma once

#include <expected>
#include <span>
#include <chrono>
#include <unistd.h>
#include <cstring>
#include <string>
#include <format>
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
     * 
     * @param address       The address info of the server to connect to.
     */
    explicit TcpSocket(TLogger* logger, AddressInfo address) noexcept
        : ISocket(), logger_(logger), address_(std::move(address))
    {
    }

    ~TcpSocket() noexcept override
    {
        if (fd_ != -1)
            this->close(true);
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
    [[nodiscard]] int fd() const noexcept
    {
        return fd_;
    }

    /**
     * Initialize the socket and set options.
     * This function must be called before `connect`.
     */
    [[nodiscard]] expected<void, WSError> init() noexcept
    {
        if (fd_ != -1)
            return WS_ERROR(logic_error, "TCP socket already initialized", close_code::not_set);

#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(
            std::format("Creating socket (family={})", address_.family())
        );
#endif

        // create a socket based on family (IPv4 or IPv6)
        fd_ = ::socket(address_.family(), SOCK_STREAM, 0);
        if (fd_ == -1)
        {
            int error_code = errno;
            return WS_ERROR(
                transport_error,
                std::format(
                    "Error creating TCP socket: {} ({})", std::strerror(error_code), error_code
                ),
                close_code::not_set
            );
        }

        // set non-blocking mode by default
        WS_TRYV(this->set_O_NONBLOCK(true));

        // disable Nagle's algorithm by default
        WS_TRYV(this->set_TCP_NODELAY(true));

        // enable quickack by default (if available on platform)
        WS_TRYV(this->set_TCP_QUICKACK(true));

#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(std::format("Socket created (fd={})", fd_)
        );
#endif

        return {};
    }

    /**
     * Establish a connection to the server.
     */
    [[nodiscard]] expected<void, WSError> connect(
        std::chrono::milliseconds timeout_ms = 5s
    ) noexcept
    {
        if (fd_ == -1)
            return WS_ERROR(
                logic_error, "TcpSocket not initialized, call init() first.", close_code::not_set
            );

        if (connected_)
            return WS_ERROR(logic_error, "Connection already established", close_code::not_set);

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
            return std::unexpected(make_error(-1, "connecting to the server"));

        // use select to wait for the connection or timeout
        WS_TRY(connected, this->wait_writeable(timeout));
        if (!connected.value())
            return WS_ERROR(timeout_error, "Connect timeout", close_code::not_set);

        // check if the connection was successful
        int error;
        socklen_t len = sizeof(error);
        ret = getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len);
        WS_TRYV(this->check_error(ret, "getsockopt"));
        if (error != 0)
        {
            std::string error_message = std::strerror(error);
            return WS_ERROR(
                transport_error,
                std::format(
                    "Connect failed to {}:{} ({}): {} (error code {})",
                    address_.hostname(),
                    address_.port(),
                    address_.ip(),
                    error_message,
                    error
                ),
                close_code::not_set
            );
        }

        connected_ = true;

#if WS_CLIENT_LOG_TCP > 0
        if (logger_->template is_enabled<LogLevel::I, LogTopic::TCP>())
        {
            auto elapsed = timeout.template elapsed<std::chrono::microseconds>();
            logger_->template log<LogLevel::I, LogTopic::TCP>(std::format(
                "Connected to {}:{} ({}) in {} µs",
                address_.hostname(),
                address_.port(),
                address_.ip(),
                elapsed.count()
            ));
        }
#endif

        return {};
    }

    /**
     * Enable or disable TCP_NODELAY option (Nagle's algorithm).
     * Disabling Nagle's algorithm can reduce latency due to reduced buffering.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_NODELAY(bool value) noexcept
    {
        int flag = value ? 1 : 0;
        int ret = setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_error(ret, "set TCP_NODELAY"));
#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(std::format("TCP_NODELAY={}", value));
#endif
        return {};
    }

    /**
     * Enable or disable O_NONBLOCK option (non-blocking mode).
     */
    [[nodiscard]] expected<void, WSError> set_O_NONBLOCK(bool value) noexcept
    {
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags == -1)
            return WS_ERROR(transport_error, "Failed to get socket flags", close_code::not_set);

        if (value)
            flags |= O_NONBLOCK;
        else
            flags &= ~O_NONBLOCK;

        if (fcntl(fd_, F_SETFL, flags) == -1)
            return WS_ERROR(
                transport_error, "Failed to set socket to non-blocking", close_code::not_set
            );

#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(std::format("O_NONBLOCK={}", value));
#endif

        return {};
    }

    /**
     * Set SO_RCVBUF option (receive buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_RCVBUF(int buffer_size) noexcept
    {
        int ret = setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_error(ret, "set SO_RCVBUF"));
#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(
            std::format("socket receive buffer size SO_RCVBUF={}", buffer_size)
        );
#endif
        return {};
    }

    /**
     * Set SO_SNDBUF option (send buffer size).
     */
    [[nodiscard]] expected<void, WSError> set_SO_SNDBUF(int buffer_size) noexcept
    {
        int ret = setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        WS_TRYV(this->check_error(ret, "set SO_SNDBUF"));
#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(
            std::format("socket send buffer size SO_SNDBUF={}", buffer_size)
        );
#endif
        return {};
    }

    /**
     * Enable or disable TCP_QUICKACK option.
     * Enabling TCP_QUICKACK can reduce latency by disabling delayed ACKs.
     * 
     * Note: TCP_QUICKACK is not available on macOS, hence a no-op on that platform.
     */
    [[nodiscard]] expected<void, WSError> set_TCP_QUICKACK(bool value) noexcept
    {
        // suppress unused parameter warning in case TCP_QUICKACK is not available
        (void)value;
#ifdef TCP_QUICKACK
        int flag = value ? 1 : 0;
        int ret = setsockopt(fd_, IPPROTO_TCP, TCP_QUICKACK, (char*)&flag, sizeof(int));
        WS_TRYV(this->check_error(ret, "set TCP_QUICKACK"));
#if WS_CLIENT_LOG_TCP > 0
        logger_->template log<LogLevel::D, LogTopic::TCP>(std::format("TCP_QUICKACK={}", value));
#endif
#endif
        return {};
    }

    /**
     * Waits for the socket to become readable, without consuming any data.
     * Readable is defined as having data application available to read.
     */
    inline expected<bool, WSError> wait_readable(Timeout<>& timeout) noexcept
    {
        // create fd_set for select with timeout
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd_, &read_fds);

        while (true)
        {
            auto remaining = timeout.remaining_timeval();
            int ret = ::select(fd_ + 1, &read_fds, nullptr, nullptr, &remaining);

            if (ret > 0) [[likely]]
            {
                // socket is readable
                return true;
            }
            else if (ret == 0)
            {
                // timeout
                return false;
            }
            else
            {
                if (errno == EINTR)
                    continue; // interrupted, retry immediately
                return make_error(ret, "Unexpected error in wait_readable");
            }
        }
    }

    /**
     * Waits for the socket to become writable.
     * Writable is defined as being able to write data to the socket.
     */
    inline expected<bool, WSError> wait_writeable(Timeout<>& timeout) noexcept
    {
        // create fd_set for select with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd_, &write_fds);

        while (true)
        {
            auto remaining = timeout.remaining_timeval();
            int ret = ::select(fd_ + 1, nullptr, &write_fds, nullptr, &remaining);

            if (ret > 0) [[likely]]
            {
                // socket is writable
                return true;
            }
            else if (ret == 0)
            {
                // timeout
                return false;
            }
            else
            {
                if (errno == EINTR)
                    continue; // interrupted, retry immediately
                return make_error(ret, "Unexpected error in wait_writeable");
            }
        }
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
        while (true)
        {
            constexpr int flags = MSG_NOSIGNAL; // prevent SIGPIPE signal on broken pipe
            ssize_t ret = ::recv(fd_, buffer.data(), buffer.size(), flags);

            if (ret > 0) [[likely]]
            {
                // data read successfully
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                // connection closed
                return WS_ERROR(
                    connection_closed, "Connection closed on transport layer", close_code::not_set
                );
            }
            else
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) [[likely]]
                {
                    // would block, wait for readability, then try recv again
                    WS_TRY(readable, this->wait_readable(timeout));
                    if (!readable.value())
                    {
                        return WS_ERROR(
                            timeout_error, "Socket read timed out", close_code::not_set
                        );
                    }
                }
                else if (errno == EINTR)
                    continue; // interrupted, retry immediately
                else
                    return make_error(ret, "Unexpected recv error in socket read operation");
            }
        }
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
        while (true)
        {
            constexpr int flags = MSG_NOSIGNAL; // prevent SIGPIPE signal on broken pipe
            ssize_t ret = ::send(fd_, buffer.data(), buffer.size(), flags);

            if (ret > 0) [[likely]]
            {
                // data written successfully
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                // connection closed
                return WS_ERROR(
                    connection_closed, "Connection closed on transport layer", close_code::not_set
                );
            }
            else
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) [[likely]]
                {
                    // would block, wait for writeability, then try send again
                    WS_TRY(readable, this->wait_writeable(timeout));
                    if (!readable.value())
                    {
                        return WS_ERROR(
                            timeout_error, "Socket write timed out", close_code::not_set
                        );
                    }
                }
                else if (errno == EINTR)
                    continue; // interrupted, retry immediately
                else
                    return make_error(ret, "Unexpected send error in socket write operation");
            }
        }
    }

    /**
     * Shuts down socket communication.
     * This function should be called before closing the socket for a clean shutdown.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    virtual expected<void, WSError> shutdown(
        bool fail_connection, Timeout<>& timeout
    ) noexcept override
    {
        if (!fail_connection)
        {
            if (fd_ != -1)
            {
#if WS_CLIENT_LOG_TCP > 0
                logger_->template log<LogLevel::D, LogTopic::TCP>(
                    std::format("Shutting down socket (fd={})", fd_)
                );
#endif

                int ret = ::shutdown(fd_, SHUT_RDWR);
                if (ret != 0)
                {
                    auto err = make_error(ret, "Shutdown of socket failed");
#if WS_CLIENT_LOG_TCP > 0
                    logger_->template log<LogLevel::W, LogTopic::TCP>(err.error().to_string());
#endif
                    return err;
                }
            }
        }
        return {};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     * 
     * @param fail_connection  If `true`, the connection is failed immediately,
     *                         e.g. in case of an error. If `false`, the connection
     *                         is gracefully closed.
     */
    virtual expected<void, WSError> close(bool fail_connection) noexcept override
    {
        if (fd_ != -1)
        {
#if WS_CLIENT_LOG_TCP > 0
            logger_->template log<LogLevel::D, LogTopic::TCP>(
                std::format("Closing socket (fd={})", fd_)
            );
#endif

            int ret = ::close(fd_);
            if (ret != 0)
            {
                auto err = make_error(ret, "Socket close failed");
#if WS_CLIENT_LOG_TCP > 0
                logger_->template log<LogLevel::W, LogTopic::TCP>(err.error().to_string());
#endif
                return err;
            }
            fd_ = -1;
        }
        return {};
    }

private:
    [[nodiscard]] std::unexpected<WSError> make_error(ssize_t ret_code, const string& desc) noexcept
    {
        int errno_ = errno;
        string msg = std::format(
            "{} (return code {}): {} ({})", desc, ret_code, std::strerror(errno_), errno_
        );
        return WS_ERROR(transport_error, std::move(msg), close_code::not_set);
    }

    [[nodiscard]] expected<void, WSError> check_error(ssize_t ret_code, const string& desc) noexcept
    {
        if (ret_code != -1)
            return {};
        return make_error(ret_code, desc);
    }
};

} // namespace ws_client
