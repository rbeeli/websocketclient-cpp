#pragma once

#include <expected>
#include <ostream>
#include <format>
#include <string>
#include <vector>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdint>
#include <chrono>

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/transport/builtin/AddressInfo.hpp"

namespace ws_client
{
using std::string;
using std::vector;

/**
 * Resolves hostname to IP address.
 * Supports IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) address families.
 * 
 * @tparam TLogger       Logger type for logging messages and errors.
 */
template <typename TLogger>
class DnsResolver final
{
    TLogger* logger;

public:
    explicit DnsResolver(TLogger* logger) noexcept : logger(logger)
    {
    }

    /**
     * Resolves hostname to IP address.
     * Uses `getaddrinfo` POSIX blocking function for resolution.
     * If no address is found, an error is returned.
     * 
     * @param hostname          Hostname to resolve, e.g. "example.com"
     * @param service           Service name or port number, e.g. "80", "http", "https", etc.
     * @param type              Address type to resolve, e.g. `AddrType::IPv4`, `AddrType::IPv6`,
     *                          `AddrType::unspecified`
     * @param resolve_canonname Whether to resolve canonical name of the host
     * 
     * @return Vector of `AddressInfo` objects, each containing resolved IP address and other info.
     */
    expected<vector<AddressInfo>, WSError> resolve(
        const string& hostname,
        const string& service,
        AddrType type = AddrType::unspecified,
        bool resolve_canonname = false
    ) const noexcept
    {
        auto now = std::chrono::system_clock::now();

        addrinfo hints{};
        switch (type)
        {
            case AddrType::unspecified:
                hints.ai_family = AF_UNSPEC;
                break;
            case AddrType::ipv4:
                hints.ai_family = AF_INET;
                break;
            case AddrType::ipv6:
                hints.ai_family = AF_INET6;
                break;
        }
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_addr = nullptr;
        if (resolve_canonname)
            hints.ai_flags = AI_CANONNAME;

        logger->template log<LogLevel::D>(
            std::format("Resolving hostname {} (type={})", hostname, to_string(type))
        );

        // resolve hostname to IP address using getaddrinfo POSIX function
        addrinfo* getaddrinfo_res;
        auto ret = ::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &getaddrinfo_res);
        if (ret != 0)
        {
            return WS_ERROR(
                url_error,
                std::format("Failed to resolve hostname: {}", gai_strerror(ret)),
                close_code::not_set
            );
        }

        if (logger->template is_enabled<LogLevel::I>())
        {
            logger->template log<LogLevel::I>(std::format(
                "Resolved hostname {} in {} µs",
                hostname,
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now() - now
                )
                    .count()
            ));
        }

        vector<AddressInfo> result;
        for (auto res = getaddrinfo_res; res != nullptr; res = res->ai_next)
        {
            if (res->ai_family == AF_INET &&
                (type == AddrType::ipv4 || type == AddrType::unspecified))
            {
                // IPv4
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(res->ai_addr);
                in_addr* address = &(ipv4->sin_addr);

                char ipCStr[INET_ADDRSTRLEN];
                if (inet_ntop(res->ai_family, address, ipCStr, sizeof(ipCStr)) != nullptr)
                {
                    result.emplace_back(
                        hostname,
                        AddrType::ipv4,
                        string(ipCStr),
                        res->ai_family,
                        res->ai_addrlen,
                        res->ai_addr,
                        string(res->ai_canonname ? res->ai_canonname : "")
                    );
                }
                else
                {
                    int error_code = errno;
                    return WS_ERROR(
                        transport_error,
                        std::format(
                            "Failed to convert IPv4 address to string: {} ({})",
                            std::strerror(error_code),
                            error_code
                        ),
                        close_code::not_set
                    );
                }
            }
            else if (res->ai_family == AF_INET6 &&
                     (type == AddrType::ipv6 || type == AddrType::unspecified))
            {
                // IPv6
                sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(res->ai_addr);
                in6_addr* address = &(ipv6->sin6_addr);

                char ipCStr[INET6_ADDRSTRLEN];
                if (inet_ntop(res->ai_family, address, ipCStr, sizeof(ipCStr)) != nullptr)
                {
                    result.emplace_back(
                        hostname,
                        AddrType::ipv6,
                        string(ipCStr),
                        res->ai_family,
                        res->ai_addrlen,
                        res->ai_addr,
                        string(res->ai_canonname ? res->ai_canonname : "")
                    );
                }
                else
                {
                    int error_code = errno;
                    return WS_ERROR(
                        transport_error,
                        std::format(
                            "Failed to convert IPv6 address to string: {} ({})",
                            std::strerror(error_code),
                            error_code
                        ),
                        close_code::not_set
                    );
                }
            }
            else
            {
                // skip unsupported address families
                logger->template log<LogLevel::D>(std::format(
                    "DnsResolver skipping unsupported address family: {}", res->ai_family
                ));
                continue;
            }
        }

        ::freeaddrinfo(getaddrinfo_res);

        if (result.empty())
            return WS_ERROR(url_error, "No address found for hostname", close_code::not_set);

        return result;
    }
};
} // namespace ws_client
