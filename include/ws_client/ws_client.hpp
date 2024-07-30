#pragma once

#include "ws_client/config.hpp"

static_assert(sizeof(size_t) == 8, "WebSocketClient only supports 64-bit architectures");

#include "ws_client/errors.hpp"
#include "ws_client/log.hpp"
#include "ws_client/URL.hpp"
#include "ws_client/Buffer.hpp"
#include "ws_client/Message.hpp"
#include "ws_client/Handshake.hpp"
#include "ws_client/WebSocketClient.hpp"
