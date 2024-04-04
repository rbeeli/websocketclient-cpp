#include <gtest/gtest.h>

#include "ws_client/utils/string.hpp"

using namespace ws_client;
using std::string;


TEST(string_utils, trim_left_with_leading_spaces)
{
    string testStr = "   leading spaces";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "leading spaces");
}

TEST(string_utils, trim_left_with_no_leading_spaces)
{
    string testStr = "no leading spaces";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "no leading spaces");
}

TEST(string_utils, trim_right_with_trailing_spaces)
{
    string testStr = "trailing spaces   ";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "trailing spaces");
}

TEST(string_utils, trim_right_with_no_trailing_spaces)
{
    string testStr = "no trailing spaces";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "no trailing spaces");
}

TEST(string_utils, trim_with_both_leading_and_trailing_spaces)
{
    string testStr = "   both sides   ";
    trim(testStr);
    EXPECT_TRUE(testStr == "both sides");
}

TEST(string_utils, trim_with_no_surrounding_spaces)
{
    string testStr = "no surrounding spaces";
    trim(testStr);
    EXPECT_TRUE(testStr == "no surrounding spaces");
}

TEST(string_utils, trim_with_only_spaces)
{
    string testStr = "   ";
    trim(testStr);
    EXPECT_TRUE(testStr.empty());
}

TEST(string_utils, trim_left_with_only_spaces)
{
    string testStr = "   ";
    trim_left(testStr);
    EXPECT_TRUE(testStr.empty());
}

TEST(string_utils, trim_right_with_only_spaces)
{
    string testStr = "   ";
    trim_right(testStr);
    EXPECT_TRUE(testStr.empty());
}

TEST(string_utils, trim_with_empty_string)
{
    string testStr = "";
    trim(testStr);
    EXPECT_TRUE(testStr.empty());
}

TEST(string_utils, trim_left_with_empty_string)
{
    string testStr = "";
    trim_left(testStr);
    EXPECT_TRUE(testStr.empty());
}

TEST(string_utils, trim_right_with_empty_string)
{
    string testStr = "";
    trim_right(testStr);
    EXPECT_TRUE(testStr.empty());
}

// more tests for tabs, newlines, etc.

// Tests for trim_left
TEST(string_utils, trim_left_with_leading_tabs)
{
    string testStr = "\t\tleading tabs";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "leading tabs");
}

TEST(string_utils, trim_left_with_leading_new_lines)
{
    string testStr = "\n\nleading new lines";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "leading new lines");
}

TEST(string_utils, trim_left_with_leading_carriage_returns)
{
    string testStr = "\r\rleading carriage returns";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "leading carriage returns");
}

TEST(string_utils, trim_right_with_trailing_tabs)
{
    string testStr = "trailing tabs\t\t";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "trailing tabs");
}

TEST(string_utils, trim_right_with_trailing_new_lines)
{
    string testStr = "trailing new lines\n\n";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "trailing new lines");
}

TEST(string_utils, trim_right_with_trailing_carriage_returns)
{
    string testStr = "trailing carriage returns\r\r";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "trailing carriage returns");
}

TEST(string_utils, trim_with_leading_and_trailing_tabs)
{
    string testStr = "\t\tboth sides\t\t";
    trim(testStr);
    EXPECT_TRUE(testStr == "both sides");
}

TEST(string_utils, trim_with_leading_and_trailing_new_lines)
{
    string testStr = "\n\nboth sides\n\n";
    trim(testStr);
    EXPECT_TRUE(testStr == "both sides");
}

TEST(string_utils, trim_with_leading_and_trailing_carriage_returns)
{
    string testStr = "\r\rboth sides\r\r";
    trim(testStr);
    EXPECT_TRUE(testStr == "both sides");
}

TEST(string_utils, trim_with_mixed_whitespace_characters)
{
    string testStr = " \t\r\nmixed whitespace characters \t\r\n";
    trim(testStr);
    EXPECT_TRUE(testStr == "mixed whitespace characters");
}

TEST(string_utils, trim_left_with_mixed_whitespace_characters)
{
    string testStr = " \t\r\nmixed whitespace characters";
    trim_left(testStr);
    EXPECT_TRUE(testStr == "mixed whitespace characters");
}

TEST(string_utils, trim_right_with_mixed_whitespace_characters)
{
    string testStr = "mixed whitespace characters \t\r\n";
    trim_right(testStr);
    EXPECT_TRUE(testStr == "mixed whitespace characters");
}
