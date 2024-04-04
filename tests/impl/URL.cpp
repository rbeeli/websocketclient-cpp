#include <gtest/gtest.h>

#include "ws_client/URL.hpp"

using namespace ws_client;

TEST(URL, basic_http)
{
    auto res = URL::parse("http://domain.tld");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, basic_HTTP_uppercase)
{
    auto res = URL::parse("HTTP://domain.tld");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, ipv6_localhost_short_with_port)
{
    auto res = URL::parse("ws://[::1]:8765");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "ws");
    EXPECT_TRUE(url.host() == "::1");
    EXPECT_TRUE(url.port() == 8765);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, ipv6_1_long)
{
    auto res = ws_client::URL::parse("ws://[0000:0000:0000:0000:0000:0000:0000:0001]");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "ws");
    EXPECT_TRUE(url.host() == "0000:0000:0000:0000:0000:0000:0000:0001");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, ipv6_1_shortened)
{
    auto res = ws_client::URL::parse("wss://[0:0:0:0:0:0:0:1]/");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "wss");
    EXPECT_TRUE(url.host() == "0:0:0:0:0:0:0:1");
    EXPECT_TRUE(url.port() == 443);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, standard_with_path_resource)
{
    auto res = ws_client::URL::parse("http://domain.tld/path/to/resource");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/path/to/resource");
}

TEST(URL, complex_unicode_arabic)
{
    auto res = ws_client::URL::parse(
        "http://sub.example.إختبار:8090/\xcf\x80?a=1&c=2&b=\xe2\x80\x8d\xf0\x9f\x8c\x88");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "sub.example.إختبار");
    EXPECT_TRUE(url.port() == 8090);
    EXPECT_TRUE(url.resource() == "/π?a=1&c=2&b=\xe2\x80\x8d\xf0\x9f\x8c\x88");
}

TEST(URL, standard_with_query_parameters)
{
    auto res = ws_client::URL::parse("http://domain.tld/path?param1=value1&param2=value2");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/path?param1=value1&param2=value2");
}

TEST(URL, standard_with_port)
{
    auto res = ws_client::URL::parse("http://domain.tld:8080");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 8080);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, standard_with_fragment)
{
    auto res = ws_client::URL::parse("http://domain.tld/path#section");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/path#section");
}

TEST(URL, standard_host_only)
{
    auto res = ws_client::URL::parse("http://domain.tld");
    EXPECT_TRUE(res.has_value());
    URL url = *res;

    EXPECT_TRUE(url.protocol() == "http");
    EXPECT_TRUE(url.host() == "domain.tld");
    EXPECT_TRUE(url.port() == 80);
    EXPECT_TRUE(url.resource() == "/");
}

TEST(URL, invalid_protocol)
{
    EXPECT_TRUE(!URL::parse("ht@://domain.tld").has_value());
}

TEST(URL, invalid_empty)
{
    EXPECT_TRUE(!URL::parse("").has_value());
}

TEST(URL, invalid_without_protocol)
{
    EXPECT_TRUE(!URL::parse("domain.tld/path").has_value());
}
