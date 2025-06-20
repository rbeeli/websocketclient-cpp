#pragma once

#include <string>

namespace ws_client
{
/**
 * Base64 encodes binary data as string.
 */
inline std::string base64_encode(const unsigned char* data, const size_t len)
{
    static constexpr char encode_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3)
    {
        unsigned int octet_a = i < len ? data[i] : 0;
        unsigned int octet_b = i + 1 < len ? data[i + 1] : 0;
        unsigned int octet_c = i + 2 < len ? data[i + 2] : 0;

        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded.push_back(encode_table[(triple >> 18) & 0x3F]);
        encoded.push_back(encode_table[(triple >> 12) & 0x3F]);

        if (i + 1 < len)
            encoded.push_back(encode_table[(triple >> 6) & 0x3F]);
        else
            encoded.push_back('=');

        if (i + 2 < len)
            encoded.push_back(encode_table[triple & 0x3F]);
        else
            encoded.push_back('=');
    }

    return encoded;
}

/**
 * Base64 encodes binary data as string.
 */
inline std::string base64_encode(const std::string& str)
{
    const unsigned char* data = reinterpret_cast<const unsigned char*>(str.data());
    const size_t len = str.size();
    return base64_encode(data, len);
}

} // namespace ws_client
