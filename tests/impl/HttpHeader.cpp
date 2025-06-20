#include <gtest/gtest.h>
#include <string>

#include "ws_client/HttpHeader.hpp"

using namespace ws_client;
using std::string;


// ----------------------------------------------------------------------------
// HttpHeaderFields
// ----------------------------------------------------------------------------

// Test for adding a single header field
TEST(HttpHeaderFields, AddSingleHeader)
{
    HttpHeaderFields headers;
    headers.add("Content-Type", "text/html");
    auto result = headers.get("Content-Type");
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result.front(), "text/html");
}

// Test for adding multiple headers with the same key
TEST(HttpHeaderFields, AddMultipleSameKeyHeaders)
{
    HttpHeaderFields headers;
    headers.add("Set-Cookie", "id=123");
    headers.add("Set-Cookie", "session=xyz");
    auto result = headers.get("Set-Cookie");
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "id=123");
    EXPECT_EQ(result[1], "session=xyz");
}

// Test for adding a header only if it's missing
TEST(HttpHeaderFields, AddIfMissing)
{
    HttpHeaderFields headers;
    headers.add("Host", "example.com");
    headers.add_if_missing("Host", "another.com");
    auto result = headers.get("Host");
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result.front(), "example.com");
}

// Test for setting a header (should replace if exists)
TEST(HttpHeaderFields, SetHeader)
{
    HttpHeaderFields headers;
    headers.add("Authorization", "Basic abc123");
    headers.set("Authorization", "Bearer xyz789");
    auto result = headers.get("Authorization");
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result.front(), "Bearer xyz789");
}

// Test for getting the first header value
TEST(HttpHeaderFields, GetFirstHeader)
{
    HttpHeaderFields headers;
    headers.add("Accept", "text/plain");
    headers.add("Accept", "text/html");
    auto result = headers.get_first("Accept");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "text/plain");
}

// Test for removing a header
TEST(HttpHeaderFields, RemoveHeader)
{
    HttpHeaderFields headers;
    headers.add("User-Agent", "CustomAgent/1.0");
    headers.remove_key("User-Agent");
    EXPECT_FALSE(headers.contains_key("User-Agent"));
}

// Test for case-insensitive header key handling
TEST(HttpHeaderFields, CaseInsensitiveKey)
{
    HttpHeaderFields headers;
    headers.add("content-length", "1234");
    EXPECT_TRUE(headers.contains_key("Content-Length"));
    auto result = headers.get_first("CONTENT-LENGTH");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "1234");
}

// Test for counting headers with the same key
TEST(HttpHeaderFields, CountSameKeyHeaders)
{
    HttpHeaderFields headers;
    headers.add("Accept-Encoding", "gzip");
    headers.add("Accept-Encoding", "deflate");
    size_t count = headers.count_key("Accept-Encoding");
    EXPECT_EQ(count, 2);
}


// ----------------------------------------------------------------------------
// HttpRequestHeader::ostream <<
// ----------------------------------------------------------------------------

TEST(HttpRequestHeader_ostream_operator, simple_test)
{
    HttpRequestHeader req;
    req.request_line.method = "GET";
    req.request_line.request_target = "/index.html";
    req.request_line.http_version = "HTTP/1.1";
    req.fields.fields = {
        {"Host", "example.com"},       //
        {"User-Agent", "Mozilla/5.0"}, //
        {"Accept", "text/html"}
    };

    std::ostringstream stream;
    stream << req;
    std::string expected = "GET /index.html HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: Mozilla/5.0\r\n"
                      "Accept: text/html\r\n\r\n";
    std::string actual = stream.str();
    EXPECT_EQ(actual, expected);
}

TEST(HttpRequestHeader_ostream_operator, test_multiple_same_key)
{
    HttpRequestHeader req;
    req.request_line.method = "GET";
    req.request_line.request_target = "/index.html";
    req.request_line.http_version = "HTTP/1.1";
    req.fields.fields = {
        {"Host", "example.com"},       //
        {"User-Agent", "Mozilla/5.0"}, //
        {"Accept", "text/html"},
        {"Accept", "application/json"}
    };

    std::ostringstream stream;
    stream << req;
    std::string expected = "GET /index.html HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: Mozilla/5.0\r\n"
                      "Accept: text/html\r\n"
                      "Accept: application/json\r\n\r\n";
    std::string actual = stream.str();
    EXPECT_EQ(actual, expected);
}

TEST(HttpRequestHeader_ostream_operator, empty_value)
{
    HttpRequestHeader req;
    req.request_line.method = "GET";
    req.request_line.request_target = "*";
    req.request_line.http_version = "HTTP/1.1";
    req.fields.fields = {{"User-Agent", ""}};

    std::ostringstream stream;
    stream << req;
    std::string expected = "GET * HTTP/1.1\r\n"
                      "User-Agent: \r\n\r\n";
    std::string actual = stream.str();
    EXPECT_EQ(actual, expected);
}
