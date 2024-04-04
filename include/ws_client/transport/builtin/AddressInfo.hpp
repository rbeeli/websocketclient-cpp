#pragma once

#include <ostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ws_client/utils/networking.hpp"

namespace ws_client
{
using std::string;
using std::vector;

enum class AddrType : uint8_t
{
    Unspecified,
    IPv4,
    IPv6
};

// to_string
string to_string(AddrType type)
{
    switch (type)
    {
        case AddrType::Unspecified:
            return "Unspecified";
        case AddrType::IPv4:
            return "IPv4";
        case AddrType::IPv6:
            return "IPv6";
        default:
            return "Unknown";
    }
}

// ostream operator
std::ostream& operator<<(std::ostream& os, AddrType type)
{
    os << to_string(type);
    return os;
}

/**
 * Represents a resolved POSIX address info.
 * 
 * Currently only supports IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) address families.
 */
class AddressInfo
{
private:
    string hostname_;
    string ip_;
    AddrType type_;
    int ai_family;
    socklen_t ai_addrlen;
    sockaddr_storage address;
    string ai_canonname;

public:
    explicit AddressInfo(
        string hostname,
        AddrType type,
        string ip,
        int ai_family,
        socklen_t addrlen,
        sockaddr* addr,
        string canonname
    ) noexcept
        : hostname_(std::move(hostname)),
          ip_(std::move(ip)),
          type_(type),
          ai_family(ai_family),
          ai_addrlen(addrlen),
          ai_canonname(canonname)
    {
        std::memcpy(&address, addr, addrlen);
    }

    // disable copy
    AddressInfo(const AddressInfo&) = delete;
    AddressInfo& operator=(const AddressInfo&) = delete;

    // enable move
    AddressInfo(AddressInfo&& other) noexcept
        : hostname_(std::move(other.hostname_)),
          ip_(std::move(other.ip_)),
          type_(other.type_),
          ai_family(other.ai_family),
          ai_addrlen(other.ai_addrlen),
          ai_canonname(std::move(other.ai_canonname))
    {
        std::memcpy(&address, &other.address, other.ai_addrlen);
    }
    AddressInfo& operator=(AddressInfo&& other) noexcept
    {
        if (this != &other)
        {
            hostname_ = std::move(other.hostname_);
            type_ = other.type_;
            ip_ = std::move(other.ip_);
            ai_family = other.ai_family;
            ai_addrlen = other.ai_addrlen;
            std::memcpy(&address, &other.address, other.ai_addrlen);
            ai_canonname = std::move(other.ai_canonname);
        }
        return *this;
    }

    inline AddrType type() const noexcept
    {
        return type_;
    }

    inline void set_port(uint16_t port) noexcept
    {
        if (ai_family == AF_INET)
            sockaddr_in_ptr()->sin_port = host_to_network(port);
        else if (ai_family == AF_INET6)
            sockaddr_in6_ptr()->sin6_port = host_to_network(port);
    }

    inline int port() const noexcept
    {
        if (ai_family == AF_INET)
            return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
        else if (ai_family == AF_INET6)
            return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
        return -1;
    }

    inline int family() const noexcept
    {
        return ai_family;
    }

    inline string canonname() const noexcept
    {
        return ai_canonname;
    }

    inline socklen_t addrlen() const noexcept
    {
        return ai_addrlen;
    }

    inline const string ip() const noexcept
    {
        return ip_;
    }

    inline string hostname() const noexcept
    {
        return hostname_;
    }

    inline sockaddr* sockaddr_ptr() noexcept
    {
        return reinterpret_cast<sockaddr*>(&address);
    }

    inline sockaddr_in* sockaddr_in_ptr() noexcept
    {
        return reinterpret_cast<sockaddr_in*>(&address);
    }

    inline sockaddr_in6* sockaddr_in6_ptr() noexcept
    {
        return reinterpret_cast<sockaddr_in6*>(&address);
    }

    // ostream operator <<
    friend std::ostream& operator<<(std::ostream& os, const AddressInfo& addr)
    {
        os << "AddressInfo{host=" << addr.hostname() << ", "
           << "type=" << (addr.type() == AddrType::IPv4 ? "IPv4" : "IPv6") << ", ip=" << addr.ip();
        if (!addr.ai_canonname.empty())
            os << ", canonname=" << addr.ai_canonname;
        os << "}";
        return os;
    }
};

} // namespace ws_client
