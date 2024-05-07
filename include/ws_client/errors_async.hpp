#pragma once

#include "ws_client/errors.hpp"

namespace ws_client
{
#define WS_CO_TRY(VARIABLE, EXPRESSION)                                                            \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                      \
        co_return WS_UNEXPECTED((VARIABLE).error());

#define WS_CO_TRY_RAW(VARIABLE, EXPRESSION)                                                        \
    auto&& VARIABLE = (EXPRESSION);                                                                \
    if (!(VARIABLE).has_value()) [[unlikely]]                                                      \
        co_return (VARIABLE).error();

#define WS_CO_TRYV(EXPRESSION)                                                                     \
    {                                                                                              \
        auto&& tmp = (EXPRESSION);                                                                 \
        if (!tmp.has_value()) [[unlikely]]                                                         \
            co_return WS_UNEXPECTED(tmp.error());                                                  \
    }

#define WS_CO_TRYV_RAW(EXPRESSION)                                                                 \
    {                                                                                              \
        auto&& tmp = (EXPRESSION);                                                                 \
        if (!tmp.has_value()) [[unlikely]]                                                         \
            co_return tmp.error();                                                                 \
    }
} // namespace ws_client
