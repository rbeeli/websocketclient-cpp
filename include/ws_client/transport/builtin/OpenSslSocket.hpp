#pragma once

#include <expected>
#include <string>
#include <span>
#include <mutex>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "ws_client/errors.hpp"
#include "ws_client/utils/Timeout.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/ISocket.hpp"
#include "ws_client/transport/builtin/OpenSslContext.hpp"

namespace ws_client
{
using std::string;
using std::byte;
using namespace std::chrono_literals;

static std::once_flag open_ssl_ex_once_flag;
static int open_ssl_ex_ix;

/**
 * Wraps a socket file descriptor by a SSL/TLS connection.
 *
 * This class extends the `ISocket` class and provides functionality for SSL/TLS communication.
 * It encapsulates `SSL` structure, and handles SSL connection establishment, reading, and writing.
 *
 * The passed file descriptor must be a valid socket file descriptor.
 * It is assumed that the socket is already connected to a remote host.
 * The file descriptor is managed by this class, and will be closed when the object is destroyed.
 */
template <typename TLogger>
class OpenSslSocket final : public ISocket
{
private:
    TLogger* logger_;
    TcpSocket<TLogger> socket_;
    OpenSslContext<TLogger>* ctx_;
    SSL* ssl_;
    string hostname_;
    bool verify_;

public:
    /**
     * Create a TCP socket from a hostname and a port.
     * The socket will be closed when the object is destroyed.
     * 
     * @param fd            The file descriptor of the underlying TCP socket.
     * @param hostname      The hostname to connect to.
     */
    explicit OpenSslSocket(
        TLogger* logger,
        TcpSocket<TLogger>&& socket,
        OpenSslContext<TLogger>* ctx,
        string hostname,
        bool verify
    ) noexcept
        : ISocket(),
          logger_(logger),
          socket_(std::move(socket)),
          ctx_(ctx),
          ssl_(nullptr),
          hostname_(std::move(hostname)),
          verify_(verify)
    {
    }

    ~OpenSslSocket() noexcept override
    {
        if (ssl_ != nullptr)
            this->close();
    }

    // disable copy
    OpenSslSocket(const OpenSslSocket&) = delete;
    OpenSslSocket& operator=(const OpenSslSocket&) = delete;

    // enable move
    OpenSslSocket(OpenSslSocket&& other) noexcept
        : ISocket(std::move(other)),
          logger_(other.logger_),
          socket_(std::move(other.socket_)),
          ctx_(other.ctx_),
          ssl_(other.ssl_),
          hostname_(std::move(other.hostname_)),
          verify_(other.verify_)
    {
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
        other.logger_ = nullptr;

        // update pointer to "this" in SSL application data
        set_ssl_ex_data();
    }
    OpenSslSocket& operator=(OpenSslSocket&& other) noexcept
    {
        if (this != &other)
        {
            this->close();
            logger_ = other.logger_;
            socket_ = std::move(other.socket_);
            ctx_ = other.ctx_;
            ssl_ = other.ssl_;
            hostname_ = std::move(other.hostname_);
            verify_ = other.verify_;
            other.ctx_ = nullptr;
            other.ssl_ = nullptr;
            other.logger_ = nullptr;

            // update pointer to "this" in SSL application data
            set_ssl_ex_data();
        }
        return *this;
    }

    /**
     * Returns the underlying TCP socket.
     */
    [[nodiscard]] TcpSocket<TLogger>& underlying() const noexcept
    {
        return socket_;
    }

    /**
     * Returns the underlying SSL structure.
     */
    inline SSL* ssl() const noexcept
    {
        return ssl_;
    }

    /**
     * Returns the underlying SSL context.
     */
    inline OpenSslContext<TLogger>* ctx() const noexcept
    {
        return ctx_;
    }

    /**
     * Get the current cipher used in the connection.
     */
    [[nodiscard]] string get_current_cipher() const noexcept
    {
        WS_TRYV(ensure_ssl_init());
        return SSL_get_cipher(ssl_);
    }

    /**
     * Get the current TLS version used in the connection.
     */
    [[nodiscard]] int get_current_tls_version() const noexcept
    {
        WS_TRYV(ensure_ssl_init());
        return SSL_version(ssl_);
    }

    /**
     * Set the hostname for Server Name Indication (SNI) extension.
     * 
     * This is useful when connecting to a server with multiple hostnames on the same IP address,
     * which is common in shared hosting environments.
     */
    [[nodiscard]] expected<void, WSError> set_hostname(const string& hostname) noexcept
    {
        WS_TRYV(ensure_ssl_init());

        int ret = SSL_set_tlsext_host_name(ssl_, hostname.c_str());
        if (ret != 1)
            return ssl_error(ret, "Unable to set hostname");

        logger_->template log<LogLevel::I>("hostname=" + hostname);

        return {};
    }

    /**
     * Enable or disable peer certificate verification.
     */
    [[nodiscard]] expected<void, WSError> set_verify_peer(const bool value) noexcept
    {
        WS_TRYV(ensure_ssl_init());

        if (value)
            SSL_set_verify(ssl_, SSL_VERIFY_PEER, OpenSslSocket<TLogger>::ssl_verify_callback<TLogger>);
        else
            SSL_set_verify(ssl_, SSL_VERIFY_NONE, nullptr);

        logger_->template log<LogLevel::I>("verify_peer=" + std::to_string(value));

        return {};
    }

    /**
     * Set the cipher list to use for the connection.
     * A cipher list is a set of ciphers that the client is willing to use.
     */
    [[nodiscard]] expected<void, WSError> set_cipher_list(const string& ciphers) noexcept
    {
        WS_TRYV(ensure_ssl_init());

        int ret = SSL_set_cipher_list(ssl_, ciphers.c_str());
        if (ret != 1)
            return ssl_error(ret, "Unable to set cipher list");

        logger_->template log<LogLevel::I>("cipher_list=" + ciphers);

        return {};
    }

    /**
     * Set the TLS version range to use for the connection.
     * The `min_version` and `max_version` are the minimum and maximum TLS versions to use.
     */
    [[nodiscard]] expected<void, WSError> set_tls_version_range(
        int min_version, int max_version
    ) noexcept
    {
        WS_TRYV(ensure_ssl_init());

        // set TLS min version
        int ret = SSL_set_min_proto_version(ssl_, min_version);
        if (ret != 1)
            return ssl_error(ret, "Unable to set min. TLS version: " + std::to_string(min_version));

        // set TLS max version
        ret = SSL_set_max_proto_version(ssl_, max_version);
        if (ret != 1)
            return ssl_error(ret, "Unable to set max. TLS version: " + std::to_string(max_version));

        logger_->template log<LogLevel::I>(
            "tls_version_range=" + std::to_string(min_version) + " to " +
            std::to_string(max_version)
        );

        return {};
    }

    /**
     * Initialize the SSL/TLS connection.
     * This function must be called before `connect`.
     */
    [[nodiscard]] expected<void, WSError> init() noexcept
    {
        if (ssl_)
            return WS_ERROR(logic_error, "OpenSslSocket already initialized", close_code::not_set);

        // create SSL structure
        ssl_ = SSL_new(ctx_->ssl_ctx());
        if (!ssl_)
            return ssl_error(0, "Unable to create SSL structure");

        // set SSL application data (pointer to this instance)
        set_ssl_ex_data();

        // wrap the SSL structure around the socket
        int ret = SSL_set_fd(ssl_, socket_.fd());
        if (ret != 1)
        {
            return ssl_error(
                ret,
                "Unable to create SSL object for file descriptor (fd=" +
                    std::to_string(socket_.fd()) + ")"
            );
        }

        // configure certificate verification
        WS_TRYV(this->set_verify_peer(verify_));

        // set SNI hostname
        WS_TRYV(this->set_hostname(hostname_));

        // regsiter info callback
        SSL_set_info_callback(ssl_, OpenSslSocket<TLogger>::ssl_info_callback<TLogger>);

        logger_->template log<LogLevel::D>(
            "OpenSslSocket created (fd=" + std::to_string(socket_.fd()) + ")"
        );

        return {};
    }

    /**
     * Establish a connection to the server and perform SSL handshake.
     */
    [[nodiscard]] expected<void, WSError> connect(
        std::chrono::milliseconds timeout_ms = 5s
    ) noexcept
    {
        if (!ssl_)
        {
            return WS_ERROR(
                logic_error,
                "OpenSslSocket not initialized, call init() first.",
                close_code::not_set
            );
        }

        Timeout timeout(timeout_ms);

        // connect underlying TCP socket first
        WS_TRYV(socket_.connect(timeout_ms));

        // perform SSL handshake
        int ret;
        do
        {
            ret = SSL_connect(ssl_);
            if (ret == 1) [[likely]]
                break; // SSL connection established successfully

            int ssl_err = SSL_get_error(ssl_, ret);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
            {
                // use select() to wait for the socket to get ready
                WS_TRY(ready, ssl_select(timeout, ssl_err));
                if (!ready.value())
                    return WS_ERROR(timeout_error, "SSL handshake timed out", close_code::not_set);
            }
            else if (ssl_err == SSL_ERROR_SYSCALL)
            {
                if (errno == EINTR)
                    continue; // interrupted, retry immediately
                return syscall_error(-1, "connect failed due to system error");
            }
            else if (ssl_err == SSL_ERROR_ZERO_RETURN)
            {
                return WS_ERROR(
                    connection_closed,
                    "SSL connection closed in connect (SSL_ERROR_ZERO_RETURN)",
                    close_code::not_set
                );
            }
            else
                return syscall_error(ssl_err, "connect failed due to SSL error");
        } while (ret != 1 && !timeout.is_expired());

        // Step 1: verify a server certificate was presented during the negotiation
        X509* cert = SSL_get_peer_certificate(ssl_);
        if (cert)
        {
            if (X509_check_host(cert, hostname_.c_str(), hostname_.size(), 0, nullptr) != 1)
            {
                X509_free(cert);
                return WS_ERROR(
                    transport_error,
                    "Certificate verification error: Hostname mismatch, expected: " + hostname_,
                    close_code::not_set
                );
            }
            X509_free(cert);
        }
        else
        {
            return WS_ERROR(
                transport_error,
                "Certificate verification error: No certificate presented",
                close_code::not_set
            );
        }

        // Step 2: verify the result of chain verification.
        // Verification performed according to RFC 4158.
        long verify_ret = SSL_get_verify_result(ssl_);
        if (verify_ret != X509_V_OK)
        {
            const char* err_str = X509_verify_cert_error_string(verify_ret);
            string err_desc = err_str ? err_str : "Unknown error";
            return WS_ERROR(
                transport_error,
                "Certificate chain verification failed: " + err_desc +
                    " (code: " + std::to_string(verify_ret) + ")",
                close_code::not_set
            );
        }

        return {};
    }

    /**
     * Waits for the SSL socket to become readable, without consuming any data.
     * Readable is defined as having data application available to read.
     */
    inline expected<bool, WSError> wait_readable(Timeout<>& timeout) noexcept
    {
        char buf[1];
        do
        {
            // try to read one byte without consuming it
            int ret = SSL_peek(ssl_, buf, 1);
            int ssl_err = SSL_get_error(ssl_, ret);

            if (ssl_err == SSL_ERROR_NONE) [[likely]]
            {
                // data is available to read
                return true;
            }
            else if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
            {
                // use select() to wait for the socket to get ready
                WS_TRY(ready, ssl_select(timeout, ssl_err));
                if (!ready.value())
                    return false;
            }
            else if (ssl_err == SSL_ERROR_SYSCALL)
            {
                if (errno == EINTR)
                    continue; // interrupted, retry immediately
                return syscall_error(-1, "SSL syscall error in wait_readable");
            }
            else if (ssl_err == SSL_ERROR_ZERO_RETURN)
            {
                return WS_ERROR(
                    connection_closed,
                    "SSL connection closed in wait_readable (SSL_ERROR_ZERO_RETURN)",
                    close_code::not_set
                );
            }
            else
                return ssl_error(ssl_err, "Unexpected SSL error in wait_readable");
        } while (!timeout.is_expired());

        // timeout
        return false;
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
        do
        {
            int ret = SSL_read(ssl_, buffer.data(), static_cast<int>(buffer.size()));

            if (ret > 0) [[likely]]
            {
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                return WS_ERROR(
                    transport_error, "SSL connection closed on transport layer", close_code::not_set
                );
            }
            else
            {
                int ssl_err = SSL_get_error(ssl_, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                {
                    // use select() to wait for the socket to get ready
                    WS_TRY(ready, ssl_select(timeout, ssl_err));
                    if (!ready.value())
                        return WS_ERROR(timeout_error, "SSL read timed out", close_code::not_set);
                }
                else if (ssl_err == SSL_ERROR_SYSCALL)
                {
                    if (errno == EINTR)
                        continue; // interrupted, retry immediately
                    return syscall_error(-1, "SSL syscall error in read_some");
                }
                else if (ssl_err == SSL_ERROR_ZERO_RETURN)
                {
                    return WS_ERROR(
                        connection_closed,
                        "SSL connection closed in read_some (SSL_ERROR_ZERO_RETURN)",
                        close_code::not_set
                    );
                }
                else
                    return ssl_error(ssl_err, "Unexpected SSL error in read_some");
            }
        } while (!timeout.is_expired());

        return WS_ERROR(timeout_error, "SSL read timed out", close_code::not_set);
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
        do
        {
            int ret = SSL_write(ssl_, buffer.data(), static_cast<int>(buffer.size()));
            if (ret > 0) [[likely]]
            {
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                return WS_ERROR(
                    connection_closed,
                    "SSL connection closed on transport layer",
                    close_code::not_set
                );
            }
            else
            {
                int ssl_err = SSL_get_error(ssl_, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                {
                    // use select() to wait for the socket to get ready
                    WS_TRY(ready, ssl_select(timeout, ssl_err));
                    if (!ready.value())
                        return WS_ERROR(timeout_error, "SSL write timed out", close_code::not_set);
                }
                else if (ssl_err == SSL_ERROR_SYSCALL)
                {
                    if (errno == EINTR)
                        continue; // interrupted, retry immediately
                    return syscall_error(-1, "SSL syscall error in write_some");
                }
                else if (ssl_err == SSL_ERROR_ZERO_RETURN)
                {
                    return WS_ERROR(
                        connection_closed,
                        "SSL connection closed in write_some (SSL_ERROR_ZERO_RETURN)",
                        close_code::not_set
                    );
                }
                else
                    return ssl_error(ssl_err, "Unexpected SSL error in write_some");
            }
        } while (!timeout.is_expired());

        return WS_ERROR(timeout_error, "SSL write timed out", close_code::not_set);
    }

    /**
     * Shuts down the SSL layer.
     * This function should be called before closing the socket
     * for a clean shutdown of the SSL layer.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> shutdown(Timeout<>& timeout) noexcept override
    {
        // shutdown the SSL layer
        // https://stackoverflow.com/questions/28056056/handling-ssl-shutdown-correctly
        if (ssl_)
        {
            int ret;
            do
            {
                ret = SSL_shutdown(ssl_);
                if (ret == 0)
                {
                    // wait for the peer's close_notify alert
                    continue;
                }
                else if (ret < 0)
                {
                    int ssl_err = SSL_get_error(ssl_, ret);
                    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                    {
                        // use select() to wait for the socket to get ready
                        WS_TRY(ready, ssl_select(timeout, ssl_err));
                        if (!ready.value())
                            return WS_ERROR(
                                timeout_error, "SSL shutdown timed out", close_code::not_set
                            );
                    }
                    else if (ssl_err == SSL_ERROR_SYSCALL)
                    {
                        if (errno == EINTR)
                            continue; // interrupted, retry immediately
                        return syscall_error(-1, "SSL syscall error during shutdown");
                    }
                    else
                    {
                        auto err = ssl_error(ssl_err, "SSL shutdown failed");
                        logger_->template log<LogLevel::W>(err.error().message);
                        return err;
                    }
                }
            } while (ret != 1 && !timeout.is_expired());

            logger_->template log<LogLevel::D>("SSL layer shutdown successfully");
        }

        // shutdown the underlying TCP socket
        socket_.shutdown(timeout);

        return {};
    }

    /**
     * Close the socket connection and all associated resources.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> close() noexcept override
    {
        // free the SSL structure
        if (ssl_)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
            logger_->template log<LogLevel::D>("SSL freed");
        }

        // close the underlying TCP socket
        socket_.close();

        return {};
    }

private:
    void set_ssl_ex_data() noexcept
    {
        std::call_once(open_ssl_ex_once_flag, []() { //
            open_ssl_ex_ix = SSL_get_ex_new_index(0, (void*)"OpenSslSocket", NULL, NULL, NULL);
        });
        SSL_set_ex_data(ssl_, open_ssl_ex_ix, this);
    }

    void ssl_log_error(string_view msg) noexcept
    {
        logger_->template log<LogLevel::E>(msg);
    }

    void ssl_log_debug(string_view msg) noexcept
    {
        logger_->template log<LogLevel::D>(msg);
    }

    bool ssl_log_debug_enabled() const noexcept
    {
        return logger_->template is_enabled<LogLevel::D>();
    }

    /**
     * Certificate verification callback.
     * It is called for each certificate in the chain sent by the peer
     * Starts from the root certificate, and so on.
     * 
     * @returns `1` means that the given certificate is trusted,
     *          `0` immediately aborts the SSL connection.
     */
    template <typename TLogger2>
    static int ssl_verify_callback(int preverify, X509_STORE_CTX* x509_ctx) noexcept
    {
        // For error codes, see http://www.openssl.org/docs/apps/verify.html
        // https://stackoverflow.com/questions/42272164/make-openssl-accept-expired-certificates

        // get OpenSslSocket instance from app data in SSL structure
        SSL* ssl = reinterpret_cast<SSL*>(
            X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx())
        );
        OpenSslSocket<TLogger2>* this_ = reinterpret_cast<OpenSslSocket<TLogger2>*>(
            SSL_get_ex_data(ssl, open_ssl_ex_ix)
        );

        // log certificate information for all cases
        X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        if (cert && this_->ssl_log_debug_enabled())
        {
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio)
            {
                X509_print_ex(bio, cert, XN_FLAG_MULTILINE, X509_FLAG_COMPAT);
                char* data;
                long len = BIO_get_mem_data(bio, &data);
                if (len > 0)
                {
                    string certificate_info(data, len);
                    this_->ssl_log_debug(certificate_info);
                }
                BIO_free(bio);
            }
            else
            {
                this_->ssl_log_error(
                    "Unable to print certificate information, failed to allocate BIO."
                );
                return 0;
            }
        }

        if (preverify == 0)
        {
            int err = X509_STORE_CTX_get_error(x509_ctx);
            ssl_verify_log_error(this_, err, cert);
            return 0; // abort the SSL connection
        }

        return 1;
    }

    template <typename TLogger2>
    static void ssl_verify_log_error(OpenSslSocket<TLogger2>* this_, int err, X509* cert) noexcept
    {
        switch (err)
        {
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                this_->ssl_log_error("Issuer certificate could not be found locally.");
                break;

            case X509_V_ERR_CERT_UNTRUSTED:
                this_->ssl_log_error("Certificate is not trusted.");
                break;

            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                this_->ssl_log_error("Self-signed certificate encountered in chain.");
                break;

            case X509_V_ERR_CERT_REVOKED:
                this_->ssl_log_error("Certificate has been revoked.");
                break;

            case X509_V_ERR_INVALID_CA:
                this_->ssl_log_error("Invalid CA certificate.");
                break;

            case X509_V_ERR_CERT_NOT_YET_VALID:
                if (cert)
                    this_->ssl_log_error(
                        "Certificate not valid yet for subject: " + get_cert_subject(cert)
                    );
                else
                    this_->ssl_log_error("Certificate not valid yet.");
                break;

            case X509_V_ERR_CERT_HAS_EXPIRED:
                if (cert)
                    this_->ssl_log_error(
                        "Certificate has expired for subject: " + get_cert_subject(cert)
                    );
                else
                    this_->ssl_log_error("Certificate has expired.");
                break;

            default:
                string err_str = string(X509_verify_cert_error_string(err));
                this_->ssl_log_error(
                    "Certificate verification error: " + err_str + " (code " + //
                    std::to_string(err) + ")"
                );
                break;
        }
    }

    static string get_cert_subject(X509* cert) noexcept
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio)
            return "FATAL: Unable to allocate BIO for certificate subject.";
        X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_MULTILINE);
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        if (len <= 0)
        {
            BIO_free(bio);
            return "";
        }
        string ret(data, static_cast<size_t>(len));
        BIO_free(bio);
        return ret;
    }

    template <typename TLogger2>
    static void ssl_info_callback(const SSL* ssl, int where, int ret) noexcept
    {
        OpenSslSocket<TLogger2>* this_ = reinterpret_cast<OpenSslSocket<TLogger2>*>(
            SSL_get_ex_data(ssl, open_ssl_ex_ix)
        );

        const char* str = nullptr;
        int w = where & ~SSL_ST_MASK;

        if (w & SSL_ST_CONNECT)
            str = "connect";
        else if (w & SSL_ST_ACCEPT)
            str = "accept";
        else
            str = "undefined";

        if (where & SSL_CB_LOOP)
        {
            if (this_->ssl_log_debug_enabled())
                this_->ssl_log_debug("SSL " + string(str) + ": " + SSL_state_string_long(ssl));
        }
        else if (where & SSL_CB_ALERT)
        {
            string direction = (where & SSL_CB_READ) ? "read" : "write";
            string alert_type = SSL_alert_type_string_long(ret);
            string alert_desc = SSL_alert_desc_string_long(ret);
            this_->ssl_log_error("SSL alert " + direction + " " + alert_type + ": " + alert_desc);
        }
        else if (where & SSL_CB_EXIT)
        {
            if (ret == 0)
            {
                this_->ssl_log_error(
                    "SSL " + string(str) + " failed in " + string(SSL_state_string_long(ssl))
                );
            }
            else if (ret < 0)
            {
                int err = SSL_get_error(ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                {
                    this_->ssl_log_error(
                        "SSL " + string(str) + " error in " + string(SSL_state_string_long(ssl)) +
                        " (code " + std::to_string(err) + ")"
                    );
                }
            }
        }
        else if (where & SSL_CB_HANDSHAKE_START)
        {
            this_->ssl_log_debug("SSL handshake start");
        }
        else if (where & SSL_CB_HANDSHAKE_DONE)
        {
            this_->ssl_log_debug("SSL handshake done");
        }
    }

    [[nodiscard]] expected<void, WSError> ensure_ssl_init() noexcept
    {
        if (!ssl_)
            return WS_ERROR(logic_error, "OpenSslSocket not initialized.", close_code::not_set);
        return {};
    }

    /**
     * Wait for the socket to become ready for SSL operation.
     * 
     * @returns `true` if the socket is ready, `false` if timeout occurred.
     */
    [[nodiscard]] expected<bool, WSError> ssl_select(
        Timeout<>& timeout, int ssl_err_read_write
    ) noexcept
    {
        // use select() to wait for socket to become ready for the SSL operation
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(socket_.fd(), &fds);

        // set the timeout for select
        auto remaining = timeout.remaining_timeval();
        int ret = ::select(
            socket_.fd() + 1,
            ssl_err_read_write == SSL_ERROR_WANT_READ ? &fds : nullptr,
            ssl_err_read_write == SSL_ERROR_WANT_WRITE ? &fds : nullptr,
            nullptr,
            &remaining
        );

        if (ret > 0) [[likely]]
        {
            // select() indicates readiness
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
                return true; // interrupted, retry immediately
            return syscall_error(ret, "SSL socket operation failed due to system error");
        }
    }

    [[nodiscard]] static string get_ssl_errors() noexcept
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio)
            return "FATAL: Unable to allocate BIO for SSL errors.";
        ERR_print_errors(bio);
        char* buf;
        long len = BIO_get_mem_data(bio, &buf);
        if (len <= 0)
        {
            BIO_free(bio);
            return "";
        }
        string ret(buf, static_cast<size_t>(len));
        BIO_free(bio);
        return ret;
    }

    [[nodiscard]] static std::unexpected<WSError> ssl_error(
        ssize_t ret_code, const string& desc
    ) noexcept
    {
        string errors = get_ssl_errors();
        string msg = desc + " (return code " + std::to_string(ret_code) + "): " + errors;
        return WS_ERROR(transport_error, std::move(msg), close_code::not_set);
    }

    [[nodiscard]] static std::unexpected<WSError> syscall_error(
        ssize_t ret_code, const string& desc
    ) noexcept
    {
        int errno_ = errno;
        string msg = desc + " (return code " + std::to_string(ret_code) + "): " + //
                     string(std::strerror(errno_)) + " (" + std::to_string(errno_) + ")";
        return WS_ERROR(transport_error, std::move(msg), close_code::not_set);
    }
};

} // namespace ws_client
