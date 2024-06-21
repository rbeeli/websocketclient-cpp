#pragma once

#include <expected>
#include <string>
#include <span>
#include <mutex>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/ISocket.hpp"
#include "ws_client/transport/builtin/OpenSslContext.hpp"

namespace ws_client
{
using std::string;
using std::byte;

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
    TLogger* logger;
    int fd;
    OpenSslContext<TLogger>* ctx;
    string hostname;
    bool verify;
    SSL* ssl;

public:
    /**
     * Create a TCP socket from a hostname and a port.
     * The socket will be closed when the object is destroyed.
     * 
     * @param fd            The file descriptor of the underlying TCP socket.
     * @param hostname      The hostname to connect to.
     */
    explicit OpenSslSocket(
        TLogger* logger, int fd, OpenSslContext<TLogger>* ctx, string hostname, bool verify
    ) noexcept
        : ISocket(), logger(logger), fd(fd), ctx(ctx), hostname(std::move(hostname)), verify(verify)
    {
    }

    ~OpenSslSocket() noexcept override
    {
        if (this->ssl != nullptr)
        {
            this->close();
        }
    }

    // disable copy
    OpenSslSocket(const OpenSslSocket&) = delete;
    OpenSslSocket& operator=(const OpenSslSocket&) = delete;

    // enable move
    OpenSslSocket(OpenSslSocket&& other) noexcept
        : ISocket(std::move(other)),
          logger(other.logger),
          fd(other.fd),
          ctx(other.ctx),
          hostname(std::move(other.hostname)),
          verify(other.verify),
          ssl(other.ssl)
    {
        other.fd = -1;
        other.ssl = nullptr;
        other.ctx = nullptr;
        other.logger = nullptr;

        // update pointer to "this" in SSL application data
        set_ssl_ex_data();
    }

    OpenSslSocket& operator=(OpenSslSocket&& other) noexcept
    {
        if (this != &other)
        {
            this->close();
            this->logger = other.logger;
            this->fd = other.fd;
            this->ctx = other.ctx;
            this->hostname = std::move(other.hostname);
            this->verify = other.verify;
            this->ssl = other.ssl;
            other.fd = -1;
            other.ssl = nullptr;
            other.ctx = nullptr;
            other.logger = nullptr;

            // update pointer to "this" in SSL application data
            set_ssl_ex_data();
        }
        return *this;
    }

    [[nodiscard]] int get_underlying_fd() const noexcept
    {
        return this->fd;
    }

    [[nodiscard]] expected<void, WSError> init() noexcept
    {
        // create SSL structure
        this->ssl = SSL_new(this->ctx->ssl_ctx());
        if (!this->ssl)
            return make_error("Unable to create SSL structure");

        // set SSL application data (pointer to this instance)
        set_ssl_ex_data();

        // register verify callback
        SSL_set_verify(this->ssl, SSL_VERIFY_PEER, OpenSslSocket<TLogger>::ssl_verify_callback<TLogger>);

        // regsiter info callback
        SSL_set_info_callback(this->ssl, OpenSslSocket<TLogger>::ssl_info_callback<TLogger>);

        // set SNI hostname
        WS_TRYV(this->set_hostname(this->hostname));

        // configure peer certificate verification
        WS_TRYV(this->set_verify_peer(this->verify));

        // wrap the SSL structure around the socket
        if (SSL_set_fd(this->ssl, this->fd) != 1)
            return make_error("Unable to wrap SSL structure around socket");

        logger->template log<LogLevel::D>(
            "OpenSslSocket created (fd=" + std::to_string(this->fd) + ")"
        );

        return {};
    }

    void set_ssl_ex_data()
    {
        std::call_once(open_ssl_ex_once_flag, []() { //
            open_ssl_ex_ix = SSL_get_ex_new_index(0, (void*)"OpenSslSocket", NULL, NULL, NULL);
        });
        SSL_set_ex_data(this->ssl, open_ssl_ex_ix, this);
    }

    void ssl_log_error(string_view msg)
    {
        logger->template log<LogLevel::E>(msg);
    }

    void ssl_log_debug(string_view msg)
    {
        logger->template log<LogLevel::D>(msg);
    }

    bool ssl_log_debug_enabled() const
    {
        return logger->template is_enabled<LogLevel::D>();
    }

    inline SSL* get_ssl() const noexcept
    {
        return this->ssl;
    }

    inline OpenSslContext<TLogger>* get_ctx() const noexcept
    {
        return this->ctx;
    }

    [[nodiscard]] expected<void, WSError> connect() noexcept
    {
        if (SSL_connect(this->ssl) != 1)
            return make_error("Unable to establish SSL connection");

        // Step 1: verify a server certificate was presented during the negotiation
        X509* cert = SSL_get_peer_certificate(this->ssl);
        if (cert)
        {
            if (X509_check_host(cert, this->hostname.c_str(), this->hostname.size(), 0, nullptr) !=
                1)
            {
                X509_free(cert);
                return make_error(
                    "Certificate verification error: Hostname mismatch, expected: " + hostname
                );
            }
            X509_free(cert);
        }
        else
            return make_error("Certificate verification error: No certificate presented");

        // Step 2: verify the result of chain verification.
        // Verification performed according to RFC 4158.
        if (SSL_get_verify_result(this->ssl) != X509_V_OK)
            return make_error("Certificate chain verification failed");

        return {};
    }

    [[nodiscard]] expected<void, WSError> set_hostname(const string& hostname) noexcept
    {
        if (!SSL_set_tlsext_host_name(this->ssl, hostname.c_str()))
            return make_error("Unable to set hostname");
        logger->template log<LogLevel::I>("Hostname=" + hostname);
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_verify_peer(const bool value) noexcept
    {
        SSL_set_verify(this->ssl, value ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
        logger->template log<LogLevel::I>("verify_peer=" + std::to_string(value));
        return {};
    }

    /**
     * Reads data from socket into `buffer`.
     * Does not guarantee to fill buffer completely, partial reads are possible.
     * Returns the number of bytes read.
     */
    [[nodiscard]] inline expected<size_t, WSError> read_some(span<byte> buffer) noexcept override
    {
        while (true)
        {
            int ret = SSL_read(this->ssl, buffer.data(), static_cast<int>(buffer.size()));
            if (ret > 0) [[likely]]
            {
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                return WS_ERROR(
                    TRANSPORT_ERROR, "SSL connection closed on transport layer", NOT_SET
                );
            }
            else
            {
                int err = SSL_get_error(this->ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    continue; // retry for non-blocking SSL
                }
                else if (err == SSL_ERROR_SYSCALL && errno == EINTR)
                {
                    continue; // retry on EINTR
                }
                else
                    return make_error("SSL_read failed");
            }
        }
    }

    /**
     * Writes `buffer` to underlying socket.
     * Does not guarantee to write complete `buffer` to socket, partial writes are possible.
     * Returns the number of bytes written.
     */
    [[nodiscard]] inline expected<size_t, WSError> write_some( //
        const span<byte> buffer, std::chrono::milliseconds timeout
    ) noexcept override
    {
        // TODO: Implement timeout
        while (true)
        {
            int ret = SSL_write(this->ssl, buffer.data(), static_cast<int>(buffer.size()));
            if (ret > 0) [[likely]]
            {
                return static_cast<size_t>(ret);
            }
            else if (ret == 0)
            {
                return WS_ERROR(
                    TRANSPORT_ERROR, "SSL connection closed on transport layer", NOT_SET
                );
            }
            else
            {
                int err = SSL_get_error(this->ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    continue; // retry for non-blocking SSL
                }
                else if (err == SSL_ERROR_SYSCALL && errno == EINTR)
                {
                    continue; // retry on EINTR
                }
                else
                    return make_error("SSL_write failed");
            }
        }
    }

    /**
     * Shuts down the SSL layer.
     * This function should be called before closing the socket
     * for a clean shutdown of the SSL layer.
     * The return value in case of error may be ignored by the caller.
     * Safe to call multiple times.
     */
    virtual expected<void, WSError> shutdown(std::chrono::milliseconds timeout) noexcept override
    {
        // TODO: Implement timeout
        
        // https://stackoverflow.com/questions/28056056/handling-ssl-shutdown-correctly
        if (this->ssl)
        {
            int res = SSL_shutdown(this->ssl);
            if (res == 0) // 0 means call SSL_shutdown() again, for a bidirectional shutdown
                res = SSL_shutdown(this->ssl);
            if (res != 1)
            {
                // shutdown failed
                auto err = make_error("SSL shutdown failed");
                logger->template log<LogLevel::W>(err.error().message);
                return err;
            }
            else
            {
                logger->template log<LogLevel::D>("SSL layer shut down successfully");
            }
        }
        if (this->fd != -1)
        {
            logger->template log<LogLevel::D>(
                "Shutting down socket (fd=" + std::to_string(this->fd) + ")"
            );
            int res = ::shutdown(this->fd, SHUT_RDWR);
            if (res != 0)
            {
                auto err = make_error("Unable to shut down underlying socket");
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
        if (this->ssl)
        {
            SSL_free(this->ssl);
            this->ssl = nullptr;
            logger->template log<LogLevel::D>("SSL freed");
        }
        if (this->fd != -1)
        {
            logger->template log<LogLevel::D>(
                "Closing socket (fd=" + std::to_string(this->fd) + ")"
            );
            int res = ::close(this->fd);
            if (res != 0)
            {
                auto err = make_error("Unable to close socket");
                logger->template log<LogLevel::W>(err.error().message);
                return err;
            }
            this->fd = -1;
        }
        return {};
    }

private:
    template <typename TLogger2>
    static int ssl_verify_callback(int preverify, X509_STORE_CTX* x509_ctx) noexcept
    {
        // For error codes, see http://www.openssl.org/docs/apps/verify.html
        // https://stackoverflow.com/questions/42272164/make-openssl-accept-expired-certificates

        int err = X509_STORE_CTX_get_error(x509_ctx);

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
            X509_print_ex(bio, cert, XN_FLAG_MULTILINE, X509_FLAG_COMPAT);
            char* data;
            long len = BIO_get_mem_data(bio, &data);
            if (len > 0)
            {
                std::string certificate_info(data, len);
                this_->ssl_log_debug(certificate_info);
            }
            BIO_free(bio);
        }

        if (preverify == 0)
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
                case X509_V_ERR_CERT_NOT_YET_VALID:
                case X509_V_ERR_CERT_HAS_EXPIRED:
                {
                    if (cert)
                    {
                        BIO* bio = BIO_new(BIO_s_mem());
                        X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_MULTILINE);
                        char* data;
                        long len = BIO_get_mem_data(bio, &data);
                        if (len > 0)
                        {
                            std::string subject(data, len);
                            this_->ssl_log_error(
                                "Certificate not valid yet or expired for subject:\n" + subject
                            );
                        }
                        BIO_free(bio);
                    }
                }
                break;
                default:
                    this_->ssl_log_error("Unhandled X509 verification error.");
                    break;
            }
        }

        if (err == X509_V_OK)
            return 1;

        return preverify;
    }

    template <typename TLogger2>
    static void ssl_info_callback(const SSL* ssl, int where, int ret)
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
            std::string direction = (where & SSL_CB_READ) ? "read" : "write";
            std::string alert_type = SSL_alert_type_string_long(ret);
            std::string alert_desc = SSL_alert_desc_string_long(ret);
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
                this_->ssl_log_error(
                    "SSL " + string(str) + " error in " + string(SSL_state_string_long(ssl))
                );
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

    [[nodiscard]] static string get_errors_as_string() noexcept
    {
        BIO* bio = BIO_new(BIO_s_mem());
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

    [[nodiscard]] static unexpected<WSError> make_error(const string& msg) noexcept
    {
        auto errors = get_errors_as_string();
        return WS_UNEXPECTED(WSError(WSErrorCode::TRANSPORT_ERROR, msg + ": " + errors));
    }
};

} // namespace ws_client