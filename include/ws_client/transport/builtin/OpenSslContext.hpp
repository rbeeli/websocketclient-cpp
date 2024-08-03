#pragma once

#include <expected>
#include <string>
#include <span>
#include <csignal>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"

namespace ws_client
{
using std::string;
using std::byte;

template <typename TLogger>
class OpenSslContext
{
private:
    TLogger* logger;
    SSL_CTX* ctx;


public:
    explicit OpenSslContext(TLogger* logger) noexcept //
        : logger(logger), ctx(nullptr)
    {
        // ignore SIGPIPE signal, which would terminate the process,
        // return EPIPE error code instead when writing to a closed socket
        std::signal(SIGPIPE, SIG_IGN);
    }

    ~OpenSslContext() noexcept
    {
        if (this->ctx)
        {
            SSL_CTX_free(this->ctx);
            this->ctx = nullptr;
        }
        this->logger = nullptr;
    }

    // disable copy
    OpenSslContext(const OpenSslContext&) = delete;
    OpenSslContext& operator=(const OpenSslContext&) = delete;

    // enable move
    OpenSslContext(OpenSslContext&& other) noexcept : ctx(other.ctx)
    {
        other.ctx = nullptr;
    }
    OpenSslContext& operator=(OpenSslContext&& other) noexcept
    {
        if (this != &other)
        {
            if (this->ctx)
                SSL_CTX_free(this->ctx);
            this->logger = other.logger;
            this->ctx = other.ctx;
            other.ctx = nullptr;
        }
        return *this;
    }

    [[nodiscard]] SSL_CTX* ssl_ctx() const noexcept
    {
        return this->ctx;
    }

    [[nodiscard]] expected<void, WSError> init() noexcept
    {
        // create SSL context
        this->ctx = SSL_CTX_new(TLS_client_method());
        if (!this->ctx)
            return make_error("Unable to create SSL context");

        // disable SSLv2 and SSLv3
        WS_TRYV(this->set_options(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION));

        // set default cipher list to use
        WS_TRYV(this->set_cipher_list("HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"));

        return {};
    }

    [[nodiscard]] expected<void, WSError> set_mode_auto_retry(const bool value) noexcept
    {
        if (value)
            SSL_CTX_set_mode(this->ctx, SSL_MODE_AUTO_RETRY);
        else
            SSL_CTX_clear_mode(this->ctx, SSL_MODE_AUTO_RETRY);
        logger->template log<LogLevel::D>("SSL_MODE_AUTO_RETRY=" + std::to_string(value));
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_default_verify_paths() noexcept
    {
        if (SSL_CTX_set_default_verify_paths(this->ctx) != 1)
            return make_error("Unable to load default CA certificates");
        logger->template log<LogLevel::I>("Loaded default certificates");
        return {};
    }

    [[nodiscard]] expected<void, WSError> load_verify_file(const string& path) noexcept
    {
        if (SSL_CTX_load_verify_file(this->ctx, path.c_str()) != 1)
            return make_error("Unable to load CA file from: " + path);
        logger->template log<LogLevel::I>("Loaded certificate file from: " + path);
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_cipher_list(string cipher_list) noexcept
    {
        if (!SSL_CTX_set_cipher_list(this->ctx, cipher_list.c_str()))
            return make_error("Unable to set cipher list to: " + cipher_list);
        logger->template log<LogLevel::D>("cipher_list=" + cipher_list);
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_options(uint64_t options) noexcept
    {
        SSL_CTX_set_options(this->ctx, options);
        logger->template log<LogLevel::D>("set_options=" + std::to_string(options));
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_session_cache_mode(int mode) noexcept
    {
        SSL_CTX_set_session_cache_mode(this->ctx, mode);
        logger->template log<LogLevel::D>("session_cache_mode=" + std::to_string(mode));
        return {};
    }

    [[nodiscard]] expected<void, WSError> set_session_cache_mode_client() noexcept
    {
        WS_TRY(res, this->set_session_cache_mode(SSL_SESS_CACHE_CLIENT));
        logger->template log<LogLevel::D>("SSL_SESS_CACHE_CLIENT=true");
        return {};
    }

private:
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

    [[nodiscard]] static auto make_error(const string& msg) noexcept
    {
        auto errors = get_errors_as_string();
        return std::unexpected(WSError(WSErrorCode::transport_error, msg + ": " + errors));
    }
};
} // namespace ws_client