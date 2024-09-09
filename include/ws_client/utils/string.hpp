#pragma once

#include <cstring>
#include <cctype>
#include <string>
#include <algorithm>
#include <string_view>
#include <span>
#include <cstddef>

namespace ws_client
{
using std::string;
using std::string_view;
using std::byte;
using std::span;

/**
 * Case-insensitive single ASCII character comparison (less than).
 */
inline bool less_ci_char(const char a, const char b) noexcept
{
    return std::tolower(static_cast<unsigned char>(a)) <
           std::tolower(static_cast<unsigned char>(b));
}

/**
 * Case-insensitive single ASCII character equality comparison.
 */
inline bool equals_ci_char(const char a, const char b) noexcept
{
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

/**
 * Case-insensitive string equality comparison.
 */
inline bool equals_ci(const string& a, const string& b) noexcept
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), equals_ci_char);
}

/**
 * Case-insensitive string equality comparison.
 */
inline bool equals_ci(const string_view lhs, const string_view rhs) noexcept
{
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin(), equals_ci_char);
}

/**
 * Case-insensitive "less than" string comparison operator.
 * E.g. useful for case-insensitive map keys.
 * 
 * Examples:
 * ```c++
 * std::map<string, int, CaseInsensitiveLess> my_map;
 * std::multimap<string, int, CaseInsensitiveLess> my_multimap;
 * ```
 */
struct CaseInsensitiveLess
{
    bool operator()(const string_view s1, const string_view s2) const noexcept
    {
        if (s1.size() != s2.size())
            return s1.size() < s2.size();

        return std::lexicographical_compare(
            s1.begin(), s1.end(), s2.begin(), s2.end(), less_ci_char
        );
    }
};

/**
 * Trim whitespace-like characters from beginning of string in-place.
 */
inline void trim_left(string& s) noexcept
{
    s.erase(
        s.begin(),
        std::find_if(s.begin(), s.end(), [](unsigned char c) { return !std::isspace(c); })
    );
}

/**
 * Trim whitespace-like characters from end of string in-place.
 */
inline void trim_right(string& s) noexcept
{
    s.erase(
        std::find_if(s.rbegin(), s.rend(), [](unsigned char c) { return !std::isspace(c); }).base(),
        s.end()
    );
}

/**
 * Trim whitespace-like characters from beginning and end of string in-place.
 */
inline void trim(string& s) noexcept
{
    trim_left(s);
    trim_right(s);
}

/**
 * Creates a string from a span of bytes.
 */
inline string string_from_bytes(span<byte> data) noexcept
{
    return string(reinterpret_cast<const char*>(data.data()), data.size());
}

struct string_like_hash
{
    using is_transparent = void;
    [[nodiscard]] size_t operator()(const char* txt) const
    {
        return std::hash<std::string_view>{}(txt);
    }
    [[nodiscard]] size_t operator()(std::string_view txt) const
    {
        return std::hash<std::string_view>{}(txt);
    }
    [[nodiscard]] size_t operator()(const std::string& txt) const
    {
        return std::hash<std::string>{}(txt);
    }
};
} // namespace ws_client