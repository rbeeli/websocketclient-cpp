#include <gtest/gtest.h>
#include <string>

#include "ws_client/HttpParser.hpp"

using namespace ws_client;
using std::string;

// ----------------------------------------------------------------------------
// HttpParser::parse_request_status_line
// ----------------------------------------------------------------------------

TEST(HttpParser_parse_header_status_line, valid_200_ok)
{
    auto result = HttpParser::parse_request_status_line("HTTP/1.1 200 OK");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().protocol_version == "HTTP/1.1");
    EXPECT_TRUE(result.value().status_code == 200);
    EXPECT_TRUE(result.value().reason == "OK");
}

TEST(HttpParser_parse_header_status_line, invalid_protocol_and_status_code_format)
{
    auto result = HttpParser::parse_request_status_line("HTP/1.1 TWOHUNDRED OK");
    EXPECT_TRUE(!result.has_value());
}

TEST(HttpParser_parse_header_status_line, missing_reason_phrase)
{
    auto result = HttpParser::parse_request_status_line("HTTP/1.1 404 ");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().reason.empty());
}

TEST(HttpParser_parse_header_status_line, status_code_not_a_number)
{
    auto result = HttpParser::parse_request_status_line("HTTP/1.1 ABC Not Found");
    EXPECT_TRUE(!result.has_value());
}

TEST(HttpParser_parse_header_status_line, empty_input_string)
{
    auto result = HttpParser::parse_request_status_line("");
    EXPECT_TRUE(!result.has_value());
}

TEST(HttpParser_parse_header_status_line, only_protocol_and_version)
{
    auto result = HttpParser::parse_request_status_line("HTTP/1.1");
    EXPECT_TRUE(!result.has_value());
}

TEST(HttpParser_parse_header_status_line, valid_status_line_with_extra_spaces)
{
    auto result = HttpParser::parse_request_status_line("  HTTP/1.1  200   OK  ");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().protocol_version == "HTTP/1.1");
    EXPECT_TRUE(result.value().status_code == 200);
    EXPECT_TRUE(result.value().reason == "OK");
}

// ----------------------------------------------------------------------------
// HttpParser::parse_header_fields
// ----------------------------------------------------------------------------

TEST(HttpParser_parse_header_fields, parse_simple_case)
{
    string str = "Content-Encoding: gzip\r\n"
                 "Content-Length: 14\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should succeed with comprehensive headers.";
    auto& fields = *result;
    EXPECT_EQ(fields.count_key("Content-Encoding"), 1u)
        << "Content-Encoding should be present once.";
    EXPECT_EQ(fields.get_first("Content-Encoding"), "gzip");
    EXPECT_EQ(fields.get_first("Content-Length"), "14");
}


TEST(HttpParser_parse_header_fields, parse_valid_headers_case_insensitive)
{
    string str = "content-type: text/html\r\n"
                 "CONTENT-LENGTH: 123\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should succeed.";
    auto& fields = *result;

    EXPECT_EQ(fields.get_first("CONTENT-Type"), "text/html");
    EXPECT_EQ(fields.get_first("CONTENT-Length"), "123");
}

TEST(HttpParser_parse_header_fields, parse_header_fields_with_multiple_same_keys_case_insensitive)
{
    string str = "set-cookie: id=123\r\n"
                 "Set-Cookie: token=abc\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should succeed.";
    auto& fields = *result;

    auto values = fields.get("Set-Cookie");
    ASSERT_EQ(values.size(), 2u);
    EXPECT_TRUE(std::find(values.begin(), values.end(), "id=123") != values.end());
    EXPECT_TRUE(std::find(values.begin(), values.end(), "token=abc") != values.end());
}

TEST(HttpParser_parse_header_fields, handle_empty_field_name)
{
    string str = ": No-Name-Header-Value\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_FALSE(result.has_value()) << "Parsing should fail due to empty field name.";
}

TEST(HttpParser_parse_header_fields, parse_empty_field_value)
{
    string str = "X-Custom-Header:\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should succeed.";
    auto& fields = *result;
    EXPECT_EQ(fields.count_key("X-Custom-Header"), 1) << "X-Custom-Header should exist.";
    EXPECT_EQ(fields.get_first("X-Custom-Header"), "") << "X-Custom-Header value should be empty.";
}

TEST(HttpParser_parse_header_fields, parse_header_missing_new_line)
{
    string str = "X-Custom-Header: X";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should succeed.";
    auto& fields = *result;
    EXPECT_EQ(fields.count_key("X-Custom-Header"), 1) << "X-Custom-Header should exist.";
    EXPECT_EQ(fields.get_first("X-Custom-Header"), "X") << "X-Custom-Header value should be empty.";
}

TEST(HttpParser_parse_header_fields, no_http_status_line)
{
    string str = "Content-Type: application/json\r\n";
    auto result = HttpParser::parse_header_fields(str);
    ASSERT_TRUE(result.has_value()) << "Parsing should not skip the non-HTTP status line.";
    auto& fields = *result;
    EXPECT_EQ(fields.get_first("Content-Type"), "application/json");
}
