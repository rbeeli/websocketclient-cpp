#pragma once

#include <expected>
#include <string>
#include <csignal>
#include <mutex>
#include <memory>
#include <format>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/ssl_utils.hpp"

inline std::once_flag ws_client_ignore_sigpipe_once_flag;

namespace ws_client
{
inline void ignore_sigpipe_once()
{
    std::call_once(
        ws_client_ignore_sigpipe_once_flag,
        []
        {
            std::signal(SIGPIPE, SIG_IGN); // installed exactly once
        }
    );
}

/**
 * Wrapper for the OpenSSL `SSL_CTX` object.
 * 
 * Note that this class installs SIG_IGN for SIGPIPE once at first use;
 * applications that need a different policy must call signal() after
 * instantiating the first instance of this class.
 */
template <typename TLogger>
class OpenSslContext
{
    TLogger* logger;
    SslCtxPtr ctx{};

public:
    explicit OpenSslContext(TLogger* logger) noexcept //
        : logger(logger)
    {
        // ignore SIGPIPE signal, which would terminate the process,
        // return EPIPE error code instead when writing to a closed socket
        ignore_sigpipe_once(); // idempotent & thread-safe
    }

    // disable copy
    OpenSslContext(const OpenSslContext&) = delete;
    OpenSslContext& operator=(const OpenSslContext&) = delete;

    // enable move
    OpenSslContext(OpenSslContext&& other) noexcept = default;
    OpenSslContext& operator=(OpenSslContext&& other) noexcept = default;

    [[nodiscard]] SSL_CTX* handle() const noexcept
    {
        assert(ctx);
        return ctx.get();
    }

    [[nodiscard]] std::expected<void, WSError> init() noexcept
    {
        if (ctx)
            return make_error("init function has been called already, can only be called once.");

        // create SSL context
        ERR_clear_error();
        SSL_CTX* raw = SSL_CTX_new(TLS_client_method());
        if (!raw)
            return make_error("Failed to create SSL context.");
        ctx.reset(raw); // takes ownership

        // disable legacy protocol versions
        WS_TRYV(this->set_min_proto_version(TLS1_2_VERSION));

        // hardening
        WS_TRYV(this->set_options(SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION));

        // TLS 1.2 cipher list
        WS_TRYV(this->set_cipher_list(
            "ECDHE+CHACHA20:ECDHE+AESGCM:DHE+CHACHA20:DHE+AESGCM:"
            "!aNULL:!eNULL:!kRSA:!3DES:!CAMELLIA:!SEED:!MD5:@STRENGTH"
        ));

        // TLS 1.3 suites
        WS_TRYV(this->set_ciphersuites(
            "TLS_AES_128_GCM_SHA256:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_256_GCM_SHA384"
        ));

        return {};
    }

    [[nodiscard]] std::expected<void, WSError> set_min_proto_version(int version) noexcept
    {
        ERR_clear_error();
        if (!SSL_CTX_set_min_proto_version(handle(), version))
            return make_error(std::format("Failed to set proto version to {}.", version));
        logger->template log<LogLevel::D, LogTopic::SSL>(
            std::format("min_proto_version={}", version)
        );
        return {};
    }

    void set_mode_auto_retry(bool enable) noexcept
    {
        if (enable)
            SSL_CTX_set_mode(handle(), SSL_MODE_AUTO_RETRY);
        else
            SSL_CTX_clear_mode(handle(), SSL_MODE_AUTO_RETRY);

        logger->template log<LogLevel::D, LogTopic::SSL>(
            std::format("SSL_MODE_AUTO_RETRY={}", enable)
        );
    }

    [[nodiscard]] std::expected<void, WSError> set_default_verify_paths() noexcept
    {
        ERR_clear_error();

        if (SSL_CTX_set_default_verify_paths(handle()) != 1)
            return make_error("Failed to load default CA certificates.");

        SSL_CTX_set_verify(handle(), SSL_VERIFY_PEER, SSL_CTX_get_verify_callback((handle())));

        logger->template log<LogLevel::I, LogTopic::SSL>("Loaded default certificates");

        return {};
    }

    [[nodiscard]] std::expected<void, WSError> load_verify_file(const std::string& path) noexcept
    {
        ERR_clear_error();

        if (SSL_CTX_load_verify_file(handle(), path.c_str()) != 1)
            return make_error(std::format("Failed to load CA file from: {}", path));

        SSL_CTX_set_verify(handle(), SSL_VERIFY_PEER, SSL_CTX_get_verify_callback((handle())));

        logger->template log<LogLevel::I, LogTopic::SSL>(
            std::format("Loaded certificate file from: {}", path)
        );

        return {};
    }

    [[nodiscard]] std::expected<void, WSError> set_cipher_list(
        const std::string& cipher_list
    ) noexcept
    {
        ERR_clear_error();
        if (!SSL_CTX_set_cipher_list(handle(), cipher_list.c_str()))
            return make_error(std::format("Failed to set cipher list to {}.", cipher_list));
        logger->template log<LogLevel::D, LogTopic::SSL>(std::format("cipher_list={}", cipher_list)
        );
        return {};
    }

    [[nodiscard]] std::expected<void, WSError> set_ciphersuites(const std::string& suites) noexcept
    {
        ERR_clear_error();
        if (!SSL_CTX_set_ciphersuites(handle(), suites.c_str()))
            return make_error(std::format("Failed to set TLS 1.3 suites to {}", suites));

        logger->template log<LogLevel::D, LogTopic::SSL>(
            std::format("ciphersuites(TLS1.3)={}", suites)
        );
        return {};
    }

    [[nodiscard]] std::expected<void, WSError> set_options(unsigned long options) noexcept
    {
        ERR_clear_error();
        auto applied = SSL_CTX_set_options(handle(), options);
        if ((applied & options) != options)
            return make_error(
                std::format(
                    "Failed to set context options mask. Tried to set {:#x}, got back {:#x}.",
                    options,
                    applied
                )
            );
        logger->template log<LogLevel::D, LogTopic::SSL>(std::format("set_options={:#x}", options));
        return {};
    }

    void set_session_cache_mode(int mode) noexcept
    {
        SSL_CTX_set_session_cache_mode(handle(), mode);
        logger->template log<LogLevel::D, LogTopic::SSL>(
            std::format("session_cache_mode={:#x}", mode)
        );
    }

    void set_session_cache_mode_client() noexcept
    {
        set_session_cache_mode(SSL_SESS_CACHE_CLIENT);
        logger->template log<LogLevel::D, LogTopic::SSL>("SSL_SESS_CACHE_CLIENT=true");
    }

private:
    [[nodiscard]] static auto make_error(const std::string& msg) noexcept
    {
        auto errors = get_ssl_errors();
        return std::unexpected(
            WSError(WSErrorCode::transport_error, std::format("{}: {}", msg, errors))
        );
    }
};
} // namespace ws_client