#pragma once

#include <string>
#include <cstring>
#include <unordered_map>
#include <expected>
#include <charconv>
#include <algorithm>

#include "ws_client/errors.hpp"

namespace ws_client
{
using std::string;

/**
 * URL parser.
 * 
 * Parses URL into protocol, host, port and resource.
 * 
 * Does NOT apply any encoding or decoding, i.e. punycode, percent-encoding, etc.
 * If the port is omitted in the URL, the default port for the protocol is used,
 * see `URL::protocol_port_map`.
 * 
 * Example:
 *      https://subdomain.domain.tld:8080/mail/?a=b&c=b
 * 
 * is decomposed into:
 *      protocol:   "https"
 *      host:       "subdomain.domain.tld"
 *      port:       8080
 *      resource:   "/mail/?a=b&c=b"
 */
class URL
{
private:
    string protocol_;
    string host_;
    int port_;
    string resource_;

    explicit URL(
        const string& protocol, const string& host, const int port, const string& resource
    ) noexcept
        : protocol_(protocol), host_(host), port_(port), resource_(resource)
    {
    }

public:
    /**
     * Map of default ports for known protocols.
     */
    inline static std::unordered_map<string, int> protocol_port_map = {
        {"https", 443}, {"wss", 443}, {"http", 80}, {"ws", 80}, {"ftp", 21}, {"ssh", 22}
    };

    /**
     * Returns the protocol part of the URL, always in lowercase.
     * 
     * Examples:
     *      "http", "https", "ws", "wss", "ftp"
     */
    [[nodiscard]] inline const string& protocol() const noexcept
    {
        return protocol_;
    }

    /**
     * Returns the host part of the URL.
     * 
     * Examples:
     *      "subdomain.domain.tld", "localhost"
     */
    [[nodiscard]] inline const string& host() const noexcept
    {
        return host_;
    }

    /**
     * Returns the numeric port as specified in the URL,
     * or the default port for the protocol if no port is specified,
     * see `URL::protocol_port_map`.
     * 
     * Examples:
     *      80, 443, 21
     */
    [[nodiscard]] inline int port() const noexcept
    {
        return port_;
    }

    /**
     * Returns the numeric port as string as specified in the URL,
     * or the default port for the protocol if no port is specified,
     * see `URL::protocol_port_map`.
     * 
     * Examples:
     *      "80", "443", "21"
     */
    [[nodiscard]] inline string port_str() const noexcept
    {
        return std::to_string(port_);
    }

    /**
     * Returns the resource part of the URL, which is everything
     * after the host and port.
     * 
     * Examples:
     *      "/mail/?a=b&c=b", "/index.html", "/"
     */
    [[nodiscard]] inline const string& resource() const noexcept
    {
        return resource_;
    }

    /**
     * Parses the passed URL string into a `URL` object.
     * Use this method to create a `URL` object from a string.
     * The constructor is private, so this is the only way to create a `URL` object
     * in order to be able to return an error if the URL is invalid.
     */
    [[nodiscard]] static expected<URL, WSError> parse(const string& url) noexcept
    {
        string u = url;
        string protocol;
        string host;
        int port = 0;
        string resource;

        // extract protocol
        size_t protocol_end_pos = u.find("://");
        if (protocol_end_pos != string::npos)
        {
            protocol = u.substr(0, protocol_end_pos);
            std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);
        }
        else
        {
            return WS_ERROR(
                url_error, "Invalid URL, protocol not found: " + url, close_code::not_set
            );
        }

        // set default port for known protocols
        WS_TRY(res, get_default_port(protocol));
        int& defaultport_ = *res;

        size_t offset = protocol_end_pos + 3; // Skip "://"

        // detect and handle IPv6 address
        size_t host_end_pos;
        if (u[offset] == '[')
        {
            // find the closing bracket for IPv6 address
            size_t ipv6_end_pos = u.find(']', offset);
            if (ipv6_end_pos == string::npos)
            {
                return WS_ERROR(
                    url_error,
                    "Invalid URL, closing bracket for IPv6 address not found: " + url,
                    close_code::not_set
                );
            }

            // exclude brackets when setting the host
            host = u.substr(offset + 1, ipv6_end_pos - offset - 1);
            host_end_pos = u.find_first_of('/', ipv6_end_pos);

            // extract port if present
            size_t port_start = ipv6_end_pos + 1;
            if (u[port_start] == ':')
            {
                string port_str = u.substr(port_start + 1, host_end_pos - port_start - 1);
                if (port_str.empty())
                {
                    port = defaultport_;
                }
                else
                {
                    WS_TRY(res, parse_port(port_str));
                    port = *res;
                }
            }
            else
            {
                port = defaultport_;
            }
        }
        else
        {
            host_end_pos = u.find_first_of('/', offset);
            size_t colon_pos = u.find(':', offset);
            if (colon_pos != string::npos &&
                (host_end_pos == string::npos || colon_pos < host_end_pos))
            {
                host = u.substr(offset, colon_pos - offset);
                string port_str = u.substr(colon_pos + 1, host_end_pos - colon_pos - 1);
                if (port_str.empty())
                {
                    port = defaultport_;
                }
                else
                {
                    WS_TRY(res, parse_port(port_str));
                    port = *res;
                }
            }
            else
            {
                host = u.substr(offset, host_end_pos - offset);
                port = defaultport_;
            }
        }

        // extract resource (everything after host/port)
        resource = (host_end_pos != string::npos ? u.substr(host_end_pos) : "/");

        return URL(protocol, host, port, resource);
    }

    /**
     * Returns the default port for the specified protocol.
     * The string must be lowercase.
     */
    [[nodiscard]] static expected<int, WSError> get_default_port(const string& protocol) noexcept
    {
        auto it = protocol_port_map.find(protocol);
        if (it != protocol_port_map.end())
            return it->second;

        return WS_ERROR(
            url_error, "Invalid URL, unknown protocol: " + protocol, close_code::not_set
        );
    }

    [[nodiscard]] static inline expected<int, WSError> parse_port(const string& input)
    {
        int port;
        auto const res = std::from_chars(input.data(), input.data() + input.size(), port);

        if (res.ec != std::errc{})
        {
            return WS_ERROR(
                url_error, "Failed to parse port number form URL: " + input, close_code::not_set
            );
        }

        return port;
    }

    [[nodiscard]] string to_string() const noexcept
    {
        return protocol_ + "://" + host_ + ":" + std::to_string(port_) + resource_;
    }

    // iostream support
    friend std::ostream& operator<<(std::ostream& os, const URL& url)
    {
        os << url.to_string();
        return os;
    }
};
} // namespace ws_client
