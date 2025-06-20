#pragma once

#include <string>
#include <string_view>
#include <format>
#include <sstream>
#include <span>
#include <cstddef>
#include <map>
#include <charconv>
#include <expected>

#include "ws_client/errors.hpp"
#include "ws_client/utils/string.hpp"
#include "ws_client/HttpHeader.hpp"

namespace ws_client
{
class HttpParser
{
public:
    static constexpr std::string_view header_terminator = "\r\n\r\n";

    /**
     * Parse HTTP status code, protocol version and message from headers.
     * Example: "HTTP/1.1 200 OK"
     */
    [[nodiscard]] static std::expected<HttpStatusLine, WSError> parse_request_status_line(
        std::istringstream& stream
    ) noexcept
    {
        HttpStatusLine result;
        std::string temp_status_code;

        if (!(stream >> result.protocol_version >> temp_status_code))
        {
            return WS_ERROR(
                protocol_error,
                "Error parsing HTTP protocol version / status code.",
                close_code::not_set
            );
        }

        // parse status code as integer
        auto [ptr, ec] = std::from_chars(
            temp_status_code.data(),
            temp_status_code.data() + temp_status_code.size(),
            result.status_code
        );
        if (ec != std::errc())
        {
            return WS_ERROR(
                protocol_error, "Status code is not a valid integer.", close_code::not_set
            );
        }

        // read the remaining part as the reason text, if present
        std::getline(stream, result.reason, '\n');
        trim(result.reason);

        return result;
    }

    /**
     * Parse HTTP header status line and header fields as vector of key-value pairs.
     * 
     * The passed headers string must start with the HTTP status line, followed by
     * one or more header lines.
     */
    [[nodiscard]] static std::expected<HttpHeaderFields, WSError> parse_header_fields(
        std::istringstream& stream
    ) noexcept
    {
        HttpHeaderFields result;

        std::string line;
        while (std::getline(stream, line))
        {
            trim(line);

            // break on empty line (header terminator)
            if (line.empty())
                break;

            auto colon_pos = line.find(':');
            if (colon_pos == std::string::npos)
            {
                return WS_ERROR(
                    protocol_error,
                    std::format("Malformed HTTP header line: {}", line),
                    close_code::not_set
                );
            }

            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = colon_pos < line.size() - 1 ? line.substr(colon_pos + 1)
                                                                   : "";

            // trim whitespace from header value
            trim(header_value);

            if (header_name.empty())
            {
                return WS_ERROR(
                    protocol_error,
                    std::format("Malformed HTTP header line: {}", line),
                    close_code::not_set
                );
            }

            result.add(header_name, header_value);
        }

        return result;
    }

    /**
     * Parse HTTP header status line and header fields as vector of key-value pairs.
     * 
     * The passed headers string must start with the HTTP status line, followed by
     * one or more header lines.
     */
    [[nodiscard]] static std::expected<HttpHeaderFields, WSError> parse_header_fields(
        const std::string& stream
    )
    {
        std::istringstream ss(stream);
        return parse_header_fields(ss);
    }


    [[nodiscard]] static std::expected<HttpStatusLine, WSError> parse_request_status_line(
        const std::string& stream
    ) noexcept
    {
        std::istringstream ss(stream);
        return parse_request_status_line(ss);
    }
};

} // namespace ws_client