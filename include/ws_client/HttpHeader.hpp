#pragma once

#include <string>
#include <vector>
#include <optional>
#include <ranges>
#include <utility>

#include "ws_client/utils/string.hpp"

namespace ws_client
{
/**
 * HTTP status code, protocol version and optional reason text.
 * Example: "HTTP/1.1 200 OK"
 */
struct HttpStatusLine
{
    /**
     * Protocol version, e.g. "HTTP/1.1"
     */
    std::string protocol_version;

    /**
     * Status code, e.g. 200, 404, 500, etc.
     */
    int status_code{0};

    /**
     * Reason text, e.g. "OK", "Not Found", "Internal Server Error", etc.
     * This field is optional and may be empty.
     */
    std::string reason;
};

/**
 * HTTP request line with method, request target and protocol version.
 * Example: "GET /index.html HTTP/1.1"
 */
struct HttpRequestLine
{
    /**
     * HTTP method, e.g. "GET", "POST", "PUT", "DELETE", etc.
     */
    std::string method;

    /**
     * Request target, e.g. "/", "/index.html", "/api/v1/resource", etc.
     */
    std::string request_target;

    /**
     * Protocol version, e.g. "HTTP/1.1"
     */
    std::string http_version;
};

struct HttpHeaderFields
{
    /**
     * List of key-value header pairs.
     * 
     * Using vector of pairs instead of map-like structure to allow
     * for multiple headers with the same key and to preserve insertion order.
     * E.g. "Set-Cookie" or "WWW-Authenticate" etc. may appear multiple times.
     */
    std::vector<std::pair<std::string, std::string>> fields;

    HttpHeaderFields() noexcept = default;
    explicit HttpHeaderFields(std::vector<std::pair<std::string, std::string>>&& fields) noexcept
        : fields(std::move(fields))
    {
    }

    /**
     * Adds a key-value header pair to the list of headers.
     * Existing headers with the same key are not replaced or altered,
     * the new header is simply added as separate entry.
     * Key-comparison is case-insensitive.
     */
    void add(const std::string& key, const std::string& value) noexcept
    {
        fields.emplace_back(key, value);
    }

    /**
     * Adds a key-value header pair to the list of headers
     * if no header with the same key exists, otherwise does nothing.
     */
    void add_if_missing(const std::string& key, const std::string& value) noexcept
    {
        if (!this->contains_key(key))
            this->add(key, value);
    }

    /**
     * Adds a key-value header pair to the list of headers.
     * If a header with the same key already exists, it is replaced.
     * Key-comparison is case-insensitive.
     */
    void set(const std::string& key, const std::string& value) noexcept
    {
        // remove all existing headers with the same key
        fields.erase(
            std::remove_if(
                fields.begin(),
                fields.end(),
                [&key](const auto& header) { return equals_ci(header.first, key); }
            ),
            fields.end()
        );

        // add the new header
        fields.emplace_back(key, value);
    }

    /**
     * Retrievs all values headers that match the given key.
     * Key-comparison is case-insensitive.
     */
    std::vector<std::string> get(const std::string& key) const noexcept
    {
        std::vector<std::string> result;
        for (const auto& header : fields)
        {
            if (equals_ci(header.first, key))
                result.push_back(header.second);
        }
        return result;
    }

    /**
     * Retrievs the first value of the header with the given key.
     * Note that the HTTP standard allows for multiple headers with the same key,
     * though it is uncommon.
     * Key-comparison is case-insensitive.
     */
    std::optional<std::string> get_first(const std::string& key) const noexcept
    {
        auto result = std::ranges::find_if(
            fields,
            [&key](const auto& header)
            {
                // case-insensitive
                return equals_ci(header.first, key);
            }
        );
        if (result != fields.end())
            return result->second;
        return {};
    }

    /**
     * Removes all headers that match the given key.
     * Key-comparison is case-insensitive.
     */
    void remove_key(const std::string& key) noexcept
    {
        fields.erase(
            std::remove_if(
                fields.begin(),
                fields.end(),
                [&key](const auto& header) { return equals_ci(header.first, key); }
            ),
            fields.end()
        );
    }

    /**
     * Checks if a header with the given key exists.
     * Key-comparison is case-insensitive.
     */
    bool contains_key(const std::string& key) const noexcept
    {
        return std::ranges::any_of(
            fields, [&key](const auto& header) { return equals_ci(header.first, key); }
        );
    }

    /**
     * Counts the number of headers with the given key.
     * Key-comparison is case-insensitive.
     */
    size_t count_key(const std::string& key) const noexcept
    {
        return std::ranges::count_if(
            fields, [&key](const auto& header) { return equals_ci(header.first, key); }
        );
    }
};

/**
 * Holds the HTTP request line and header fields of an HTTP request.
 */
struct HttpRequestHeader
{
    HttpRequestLine request_line;
    HttpHeaderFields fields;

    HttpRequestHeader() noexcept = default;
    explicit HttpRequestHeader(HttpRequestLine request_line) noexcept
        : request_line(std::move(request_line))
    {
    }
    explicit HttpRequestHeader(HttpRequestLine request_line, HttpHeaderFields fields) noexcept
        : request_line(std::move(request_line)), fields(std::move(fields))
    {
    }
    explicit HttpRequestHeader(
        HttpRequestLine request_line, std::vector<std::pair<std::string, std::string>>&& fields
    ) noexcept
        : request_line(std::move(request_line)), fields(HttpHeaderFields(std::move(fields)))
    {
    }
};

inline std::ostream& operator<<(std::ostream& stream, const HttpRequestHeader& request_header)
{
    stream << request_header.request_line.method << " "
           << request_header.request_line.request_target << " "
           << request_header.request_line.http_version << "\r\n";

    for (const auto& [key, value] : request_header.fields.fields)
    {
        stream << key << ": " << value << "\r\n";
    }

    stream << "\r\n";

    return stream;
}

/**
 * Holds the HTTP status line and header fields of an HTTP response.
 */
struct HttpResponseHeader
{
    HttpStatusLine status_line;
    HttpHeaderFields fields;

    HttpResponseHeader() noexcept = default;
    HttpResponseHeader(HttpStatusLine status_line) noexcept : status_line(std::move(status_line))
    {
    }
    HttpResponseHeader(HttpStatusLine status_line, HttpHeaderFields fields) noexcept
        : status_line(std::move(status_line)), fields(std::move(fields))
    {
    }
    HttpResponseHeader(
        HttpStatusLine status_line, std::vector<std::pair<std::string, std::string>>&& fields
    ) noexcept
        : status_line(std::move(status_line)), fields(HttpHeaderFields(std::move(fields)))
    {
    }
};

} // namespace ws_client
