#pragma once

#if WS_CLIENT_USE_SIMD_UTF8 == 1
#include <simdutf.h>
#endif

namespace ws_client
{

#if WS_CLIENT_USE_SIMD_UTF8 == 1

/**
 * Checks if the given string is a valid UTF-8 string.
 * This function is highly optimized due to the u se
 * of the `simdutf` library.
 */
inline bool is_valid_utf8(const char* str, int len) noexcept
{
    return simdutf::validate_utf8(str, len);
}

#else

/**
 * Checks if the given string is a valid UTF-8 string.
 * This function is not optimized, therefore slow, and should be used only
 * if SIMDUTF is not available.
 */
inline bool is_valid_utf8(const char* str, int len)
{
    const unsigned char* s = reinterpret_cast<const unsigned char*>(str);
    for (int i = 0; i < len;)
    {
        if (s[i] < 0x80)
        {
            // 0xxxxxxx
            i++;
        }
        else if ((s[i] & 0xe0) == 0xc0)
        {
            // 110XXXXx 10xxxxxx
            if (i + 1 >= len || (s[i + 1] & 0xc0) != 0x80 || (s[i] & 0xfe) == 0xc0) // Overlong?
                return false;
            else
                i += 2;
        }
        else if ((s[i] & 0xf0) == 0xe0)
        {
            // 1110XXXX 10Xxxxxx 10xxxxxx
            if (i + 2 >= len || (s[i + 1] & 0xc0) != 0x80 || (s[i + 2] & 0xc0) != 0x80 ||
                (s[i] == 0xe0 && (s[i + 1] & 0xe0) == 0x80) || // Overlong?
                (s[i] == 0xed && (s[i + 1] & 0xa0) == 0xa0))   // Surrogate half?
                return false;
            else
                i += 3;
        }
        else if ((s[i] & 0xf8) == 0xf0)
        {
            // 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx
            if (i + 3 >= len || (s[i + 1] & 0xc0) != 0x80 || (s[i + 2] & 0xc0) != 0x80 ||
                (s[i + 3] & 0xc0) != 0x80 ||
                (s[i] == 0xf0 && (s[i + 1] & 0xf0) == 0x80) ||    // Overlong?
                (s[i] == 0xf4 && s[i + 1] > 0x8f) || s[i] > 0xf4) // Greater than U+10FFFF?
                return false;
            else
                i += 4;
        }
        else
        {
            return false; // Invalid UTF-8 start byte
        }
    }
    return true;
}

#endif

} // namespace ws_client
