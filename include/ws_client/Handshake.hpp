#pragma once

#include <expected>
#include <sstream>
#include <string>
#include <map>
#include <optional>

#include "ws_client/errors.hpp"
#include "ws_client/utils/string.hpp"
#include "ws_client/utils/base64.hpp"
#include "ws_client/utils/random.hpp"
#include "ws_client/utils/SHA1.hpp"
#include "ws_client/HttpHeader.hpp"
#include "ws_client/HttpParser.hpp"
#include "ws_client/PermessageDeflate.hpp"
#include "ws_client/URL.hpp"

namespace ws_client
{
using std::string;

template <typename TLogger>
class Handshake
{
protected:
    TLogger* logger_;
    URL url_;
    xoshiro128p rnd_;
    string request_SecWebSocketKey_;
    HttpRequestHeader request_header_;
    HttpResponseHeader response_header_;
    std::optional<PermessageDeflate<TLogger>> permessage_deflate_{std::nullopt};
    bool permessage_deflate_negotiated_{false};
    bool success_{false};

public:
    explicit Handshake(TLogger* logger, URL url) noexcept //
        : logger_(logger), url_(url), rnd_(xoshiro128p())
    {
    }

    // disable copying
    Handshake(const Handshake&) = delete;
    Handshake& operator=(Handshake const&) = delete;

    // move constructor/assignment
    Handshake(Handshake&& other) noexcept
        : logger_(other.logger_),
          url_(std::move(other.url_)),
          rnd_(std::move(other.rnd_)),
          request_SecWebSocketKey_(std::move(other.request_SecWebSocketKey_)),
          response_header_(std::move(other.response_header_)),
          permessage_deflate_(std::move(other.permessage_deflate_)),
          permessage_deflate_negotiated_(other.permessage_deflate_negotiated_),
          success_(other.success_)
    {
    }
    Handshake& operator=(Handshake&& other) noexcept
    {
        if (this != &other)
        {
            logger_ = other.logger_;
            url_ = std::move(other.url_);
            rnd_ = std::move(other.rnd_);
            request_SecWebSocketKey_ = std::move(other.request_SecWebSocketKey_);
            response_header_ = std::move(other.response_header_);
            permessage_deflate_ = std::move(other.permessage_deflate_);
            permessage_deflate_negotiated_ = other.permessage_deflate_negotiated_;
            success_ = other.success_;
        }
        return *this;
    }

    inline bool is_compression_negotiated() const
    {
        return permessage_deflate_negotiated_;
    }

    inline bool is_compression_requested() const
    {
        return permessage_deflate_.has_value();
    }

    inline const URL& url() noexcept
    {
        return url_;
    }

    inline bool is_success() const noexcept
    {
        return success_;
    }

    /**
     * Gets the request header object sent to the server.
     * Modify this object to change the request headers,
     * i.e. to add custom headers for authentication, logging etc.
     */
    inline HttpRequestHeader& get_request_header() noexcept
    {
        return request_header_;
    }

    inline const HttpResponseHeader& get_response_header() const noexcept
    {
        return response_header_;
    }

    inline PermessageDeflate<TLogger>& get_permessage_deflate() noexcept
    {
        return permessage_deflate_.value();
    }

    inline void set_permessage_deflate(PermessageDeflate<TLogger>&& extension)
    {
        permessage_deflate_ = extension;
    }

    /**
     * Generates the HTTP request message to be sent to the server
     * for the WebSocket handshake and connection upgrade.
     * 
     * To add user-defined request headers, like authentication headers,
     * modify the request_header object before calling this method,
     * see `get_request_header()`.
    */
    string get_request_message()
    {
        auto& fields = request_header_.fields;
        request_header_.request_line = {
            .method = "GET", .request_target = url_.resource(), .http_version = "HTTP/1.1"
        };
        fields.add_if_missing("Host", url_.host() + ":" + std::to_string(url_.port()));
        fields.add_if_missing("Upgrade", "websocket");
        fields.add_if_missing("Connection", "Upgrade");
        fields.add_if_missing("Sec-WebSocket-Version", "13");
        request_SecWebSocketKey_ = generate_SecWebSocketKey();
        fields.set("Sec-WebSocket-Key", request_SecWebSocketKey_);

        // permessage-deflate extension for compression, optional
        if (permessage_deflate_.has_value() && !fields.contains_key("Sec-WebSocket-Extensions"))
        {
            fields.set(
                "Sec-WebSocket-Extensions",
                permessage_deflate_->get_Sec_WebSocket_Extensions_value()
            );
        }

        fields.add_if_missing("User-Agent", "websocketclient-cpp");

        // write request headers to string
        std::ostringstream stream;
        stream << request_header_;
        string request = stream.str();

#if WS_CLIENT_LOG_HANDSHAKE == 1
        if (logger_->template is_enabled<LogLevel::I>())
        {
            logger_->template log<LogLevel::I>(
                "Handshake HTTP request headers:\033[1;34m\n" + request + "\033[0m"
            );
        }
#endif

        return request;
    }

    [[nodiscard]] expected<void, WSError> process_response(const string& header_str)
    {
#if WS_CLIENT_LOG_HANDSHAKE == 1
        if (logger_->template is_enabled<LogLevel::I>())
        {
            logger_->template log<LogLevel::I>(
                "Handshake HTTP response headers:\033[1;35m\n" + header_str + "\033[0m"
            );
        }
#endif

        std::istringstream stream(header_str);

        // first line = status line
        WS_TRY(status_line_res, HttpParser::parse_request_status_line(stream));
        HttpStatusLine& status_line = *status_line_res;

        // validate HTTP status code
        if (status_line.status_code != 101)
        {
            return WS_ERROR(
                protocol_error,
                "HTTP error during WebSocket handshake response processing: " +
                    std::to_string(status_line.status_code) + " " + status_line.reason,
                close_code::not_set
            );
        }

        // parse response header fields
        WS_TRY(fields_res, HttpParser::parse_header_fields(stream));
        response_header_ = HttpResponseHeader(status_line, std::move(*fields_res));

        // validate "Connection: Upgrade" header
        WS_TRYV(validate_ConnectionUpgrade());

        // validate "Sec-WebSocket-Accept" header
        WS_TRYV(validate_SecWebSocketAccept());

        // validate "Sec-WebSocket-Version" header
        WS_TRYV(validate_SecWebSocketVersion());

        // negotiate & validate permessage-deflate extension
        if (permessage_deflate_.has_value())
        {
            WS_TRY(negotiate_res, permessage_deflate_->negotiate(response_header_));
            permessage_deflate_negotiated_ = *negotiate_res;
        }

        success_ = true;

        return {};
    }

protected:
    [[nodiscard]] expected<void, WSError> validate_ConnectionUpgrade()
    {
        auto h_con = response_header_.fields.get_first("Connection");
        if (!h_con.has_value())
        {
            return WS_ERROR(
                protocol_error, "HTTP response is missing 'Connection' header", close_code::not_set
            );
        }

        if (!equals_ci(*h_con, "Upgrade"))
        {
            return WS_ERROR(
                protocol_error,
                "Invalid 'Connection' header, expected: 'Upgrade', got: " + *h_con,
                close_code::not_set
            );
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> validate_SecWebSocketVersion()
    {
        auto h_ext = response_header_.fields.get_first("Sec-WebSocket-Version");
        if (!h_ext.has_value())
            return {}; // not provided by server - assume it's compatible

        if (*h_ext != "13")
        {
            return WS_ERROR(
                protocol_error,
                "Invalid 'Sec-WebSocket-Version' header, expected: 13, got: " + *h_ext,
                close_code::not_set
            );
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> validate_SecWebSocketAccept()
    {
        auto h_ext = response_header_.fields.get_first("Sec-WebSocket-Accept");
        if (!h_ext.has_value())
        {
            return WS_ERROR(
                protocol_error,
                "HTTP response is missing 'Sec-WebSocket-Accept' header",
                close_code::not_set
            );
        }

        // calculate expected accept checksum using SHA1 and base64
        SHA1 checksum;
        checksum.update(request_SecWebSocketKey_ + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        auto sha1_bytes = checksum.final_bytes();

        string expected_accept = base64_encode(sha1_bytes.data(), sha1_bytes.size());
        if (*h_ext != expected_accept)
        {
            return WS_ERROR(
                protocol_error,
                "Invalid 'Sec-WebSocket-Accept' header, expected: " + expected_accept +
                    ", got: " + *h_ext,
                close_code::not_set
            );
        }

        return {};
    }

    inline string generate_SecWebSocketKey()
    {
        unsigned char key[16];
        uint64_t part = rnd_.next();
        std::memcpy(key, &part, 8);
        part = rnd_.next();
        std::memcpy(key + 8, &part, 8);
        return base64_encode(key, sizeof(key));
    }
};

} // namespace ws_client