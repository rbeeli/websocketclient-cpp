#pragma once

#include <cerrno>
#include <cstring>
#include <string>
#include <expected>
#include <format>

#include <openssl/err.h>

#include "ws_client/errors.hpp"

namespace ws_client
{
/* ===================
 * Error handling code
 * =================== */

[[nodiscard]] constexpr std::string_view ssl_err_name(int e) noexcept
{
    switch (e)
    {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        default:
            return "SSL_ERROR_UNKNOWN";
    }
}

[[nodiscard]] inline std::string get_ssl_errors() noexcept
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
    std::string ret(buf, static_cast<size_t>(len));
    BIO_free(bio);
    return ret;
}

[[nodiscard]] inline std::unexpected<WSError> ssl_error(
    int ret_code, int ssl_err, std::string_view desc
) noexcept
{
    // get_ssl_errors() calls ERR_print_errors(), which drains the SSL error queue
    return WS_ERROR(
        transport_error,
        std::format(
            "{} (ret_code {}, ssl_err {} {}): {}",
            desc,
            ret_code,
            ssl_err,
            ssl_err_name(ssl_err),
            get_ssl_errors()
        ),
        close_code::not_set
    );
}

[[nodiscard]] inline std::unexpected<WSError> syscall_error(
    int ret_code, int errno_, std::string_view desc
) noexcept
{
    ERR_clear_error(); // manually drain SSL error queue
    std::string errno_msg = std::system_category().message(errno_);
    return WS_ERROR(
        transport_error,
        std::format("{}: {} (errno={}, ret={})", desc, errno_msg, errno_, ret_code),
        close_code::not_set
    );
}
}; // namespace ws_client
