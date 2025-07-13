#pragma once

#include <cstdint>
#include <bit>

namespace ws_client
{
/**
 * Converts 32 bit value from network byte order to host byte order.
 */
[[nodiscard]] inline uint32_t network_to_host(uint32_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap32
        return __builtin_bswap32(value);
#elif defined(_byteswap_ulong)
        return _byteswap_ulong(value);
#else
        return ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) |
               ((value & 0x0000ff00) << 8) | ((value & 0x000000ff) << 24);
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}


/**
 * Converts 16 bit value from network byte order to host byte order.
 */
[[nodiscard]] inline uint16_t network_to_host(uint16_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap16
        return __builtin_bswap16(value);
#elif defined(_byteswap_ushort)
        return _byteswap_ushort(value);
#else
        return static_cast<uint16_t>(((value & 0xff00) >> 8) | ((value & 0x00ff) << 8));
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}


/**
 * Converts 32 bit value from host byte order to network byte order.
 */
[[nodiscard]] inline uint32_t host_to_network(uint32_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap32
        return __builtin_bswap32(value);
#elif defined(_byteswap_ulong)
        return _byteswap_ulong(value);
#else
        return ((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) |
               ((value & 0x0000ff00) << 8) | ((value & 0x000000ff) << 24);
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}


/**
 * Converts 16 bit value from host byte order to network byte order.
 */
[[nodiscard]] inline uint16_t host_to_network(uint16_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap16
        return __builtin_bswap16(value);
#elif defined(_byteswap_ushort)
        return _byteswap_ushort(value);
#else
        return static_cast<uint16_t>(((value & 0xff00) >> 8) | ((value & 0x00ff) << 8));
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}


/**
 * Converts 64 bit value from host byte order to network byte order.
 */
[[nodiscard]] inline uint64_t host_to_network(uint64_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap64
        return __builtin_bswap64(value);
#elif defined(_byteswap_uint64)
        return _byteswap_uint64(value);
#else
        return ((value & 0xff00000000000000) >> 56) | ((value & 0x00ff000000000000) >> 40) |
               ((value & 0x0000ff0000000000) >> 24) | ((value & 0x000000ff00000000) >> 8) |
               ((value & 0x00000000ff000000) << 8) | ((value & 0x0000000000ff0000) << 24) |
               ((value & 0x000000000000ff00) << 40) | ((value & 0x00000000000000ff) << 56);
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}


/**
 * Converts 64 bit value from network byte order to host byte order.
 */
[[nodiscard]] constexpr uint64_t network_to_host(uint64_t value) noexcept
{
    if constexpr (std::endian::native == std::endian::little)
#ifdef __builtin_bswap64
        return __builtin_bswap64(value);
#elif defined(_byteswap_uint64)
        return _byteswap_uint64(value);
#else
        return ((value & 0xff00000000000000) >> 56) | ((value & 0x00ff000000000000) >> 40) |
               ((value & 0x0000ff0000000000) >> 24) | ((value & 0x000000ff00000000) >> 8) |
               ((value & 0x00000000ff000000) << 8) | ((value & 0x0000000000ff0000) << 24) |
               ((value & 0x000000000000ff00) << 40) | ((value & 0x00000000000000ff) << 56);
#endif
    else
        return value; // on big-endian systems, network byte order equals host byte order
}

} // namespace ws_client