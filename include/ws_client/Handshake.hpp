#pragma once

#include <expected>
#include <sstream>
#include <string>
#include <map>
#include <optional>
#include <chrono>

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
    TLogger* logger;
    URL url;
    xoshiro128p rnd;
    string request_SecWebSocketKey;
    HttpRequestHeader request_header;
    HttpResponseHeader response_header;
    std::optional<PermessageDeflate<TLogger>> permessage_deflate{std::nullopt};
    bool permessage_deflate_negotiated{false};
    bool success{false};
    std::chrono::seconds timeout{30};

public:
    explicit Handshake(TLogger* logger, URL url) noexcept //
        : logger(logger), url(url), rnd(xoshiro128p())
    {
    }

    // disable copying
    Handshake(const Handshake&) = delete;
    Handshake& operator=(Handshake const&) = delete;

    // move constructor/assignment
    Handshake(Handshake&& other) noexcept
        : logger(other.logger),
          url(std::move(other.url)),
          rnd(std::move(other.rnd)),
          request_SecWebSocketKey(std::move(other.request_SecWebSocketKey)),
          response_header(std::move(other.response_header)),
          permessage_deflate(std::move(other.permessage_deflate)),
          permessage_deflate_negotiated(other.permessage_deflate_negotiated),
          success(other.success)
    {
    }
    Handshake& operator=(Handshake&& other) noexcept
    {
        if (this != &other)
        {
            this->logger = other.logger;
            this->url = std::move(other.url);
            this->rnd = std::move(other.rnd);
            this->request_SecWebSocketKey = std::move(other.request_SecWebSocketKey);
            this->response_header = std::move(other.response_header);
            this->permessage_deflate = std::move(other.permessage_deflate);
            this->permessage_deflate_negotiated = other.permessage_deflate_negotiated;
            this->success = other.success;
        }
        return *this;
    }

    inline bool is_compression_negotiated() const
    {
        return this->permessage_deflate_negotiated;
    }

    inline bool is_compression_requested() const
    {
        return this->permessage_deflate.has_value();
    }

    inline const URL& get_url() noexcept
    {
        return this->url;
    }

    /**
     * Gets the request header object sent to the server.
     * Modify this object to change the request headers,
     * i.e. to add custom headers for authentication, logging etc.
     */
    inline HttpRequestHeader& get_request_header() noexcept
    {
        return this->request_header;
    }

    inline const HttpResponseHeader& get_response_header() const noexcept
    {
        return this->response_header;
    }

    inline PermessageDeflate<TLogger>& get_permessage_deflate() noexcept
    {
        return this->permessage_deflate.value();
    }

    inline void set_permessage_deflate(PermessageDeflate<TLogger>&& extension)
    {
        this->permessage_deflate = extension;
    }

    inline std::chrono::seconds get_timeout() const noexcept
    {
        return this->timeout;
    }

    inline void set_timeout(std::chrono::seconds timeout) noexcept
    {
        this->timeout = timeout;
    }

    inline bool is_success() const noexcept
    {
        return this->success;
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
        auto& fields = this->request_header.fields;
        this->request_header.request_line = {
            .method = "GET", .request_target = this->url.resource(), .http_version = "HTTP/1.1"
        };
        fields.add_if_missing("Host", this->url.host() + ":" + std::to_string(this->url.port()));
        fields.add_if_missing("Upgrade", "websocket");
        fields.add_if_missing("Connection", "Upgrade");
        fields.add_if_missing("Sec-WebSocket-Version", "13");
        this->request_SecWebSocketKey = this->generate_SecWebSocketKey();
        fields.set("Sec-WebSocket-Key", this->request_SecWebSocketKey);

        // permessage-deflate extension for compression, optional
        if (this->permessage_deflate.has_value() &&
            !fields.contains_key("Sec-WebSocket-Extensions"))
        {
            fields.set(
                "Sec-WebSocket-Extensions",
                this->permessage_deflate->get_Sec_WebSocket_Extensions_value()
            );
        }

        fields.add_if_missing("User-Agent", "websocketclient-cpp");

        // write request headers to string
        std::ostringstream stream;
        stream << this->request_header;
        string request = stream.str();

#if WS_CLIENT_LOG_HANDSHAKE
        if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
        {
            logger->template log<LogLevel::I>(
                "Handshake HTTP request headers:\033[1;34m\n" + request + "\033[0m"
            );
        }
#endif

        return request;
    }

    [[nodiscard]] expected<void, WSError> process_response(const string& header_str)
    {
#if WS_CLIENT_LOG_HANDSHAKE
        if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
        {
            logger->template log<LogLevel::I>(
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
                PROTOCOL_ERROR,
                "HTTP error during WebSocket handshake response processing: " +
                    std::to_string(status_line.status_code) + " " + status_line.reason,
                NOT_SET
            );
        }

        // parse response header fields
        WS_TRY(fields_res, HttpParser::parse_header_fields(stream));
        this->response_header = HttpResponseHeader(status_line, std::move(*fields_res));

        // validate "Connection: Upgrade" header
        WS_TRYV(this->validate_ConnectionUpgrade());

        // validate "Sec-WebSocket-Accept" header
        WS_TRYV(this->validate_SecWebSocketAccept());

        // validate "Sec-WebSocket-Version" header
        WS_TRYV(this->validate_SecWebSocketVersion());

        // negotiate & validate permessage-deflate extension
        if (this->permessage_deflate.has_value())
        {
            WS_TRY(negotiate_res, this->permessage_deflate->negotiate(this->response_header));
            this->permessage_deflate_negotiated = *negotiate_res;
        }

        this->success = true;

        return {};
    }

protected:
    [[nodiscard]] expected<void, WSError> validate_ConnectionUpgrade()
    {
        auto h_con = this->response_header.fields.get_first("Connection");
        if (!h_con.has_value())
        {
            return WS_ERROR(
                PROTOCOL_ERROR, "HTTP response is missing 'Connection' header", NOT_SET
            );
        }

        if (!equals_ci(*h_con, "Upgrade"))
        {
            return WS_ERROR(
                PROTOCOL_ERROR,
                "Invalid 'Connection' header, expected: 'Upgrade', got: " + *h_con,
                NOT_SET
            );
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> validate_SecWebSocketVersion()
    {
        auto h_ext = this->response_header.fields.get_first("Sec-WebSocket-Version");
        if (!h_ext.has_value())
            return {}; // not provided by server - assume it's compatible

        if (*h_ext != "13")
        {
            return WS_ERROR(
                PROTOCOL_ERROR,
                "Invalid 'Sec-WebSocket-Version' header, expected: 13, got: " + *h_ext,
                NOT_SET
            );
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> validate_SecWebSocketAccept()
    {
        auto h_ext = this->response_header.fields.get_first("Sec-WebSocket-Accept");
        if (!h_ext.has_value())
        {
            return WS_ERROR(
                PROTOCOL_ERROR, "HTTP response is missing 'Sec-WebSocket-Accept' header", NOT_SET
            );
        }

        // calculate expected accept checksum using SHA1 and base64
        SHA1 checksum;
        checksum.update(this->request_SecWebSocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        auto sha1_bytes = checksum.final_bytes();

        string expected_accept = base64_encode(sha1_bytes.data(), sha1_bytes.size());
        if (*h_ext != expected_accept)
        {
            return WS_ERROR(
                PROTOCOL_ERROR,
                "Invalid 'Sec-WebSocket-Accept' header, expected: " + expected_accept +
                    ", got: " + *h_ext,
                NOT_SET
            );
        }

        return {};
    }

    inline string generate_SecWebSocketKey()
    {
        unsigned char key[16];
        uint64_t part = this->rnd.next();
        std::memcpy(key, &part, 8);
        part = this->rnd.next();
        std::memcpy(key + 8, &part, 8);
        return base64_encode(key, sizeof(key));
    }
};

} // namespace ws_client