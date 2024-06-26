#pragma once

#ifndef WS_CLIENT_VALIDATE_UTF8
/**
 * Enables UTF-8 validation of TEXT messages, see RFC 6455, section 5.6.
 * If disabled, does not validate TEXT message payloads and CLOSE error messages.
 * Disable for improved performance.
 * Recommended to enable during development and debugging.
 */
#define WS_CLIENT_VALIDATE_UTF8 1
#endif

#ifndef WS_CLIENT_LOG_HANDSHAKE
/**
 * Enable logging of handshake / negotiation messages and HTTP headers.
 */
#define WS_CLIENT_LOG_HANDSHAKE 1
#endif

#ifndef WS_CLIENT_LOG_MSG_PAYLOADS
/**
 * Enable logging of message payloads as strings.
 */
#define WS_CLIENT_LOG_MSG_PAYLOADS 1
#endif

#ifndef WS_CLIENT_LOG_MSG_SIZES
/**
 * Enable logging of message sizes without payload.
 * WS_CLIENT_LOG_MSG_PAYLOADS has higher priority.
 */
#define WS_CLIENT_LOG_MSG_SIZES 0
#endif

#ifndef WS_CLIENT_LOG_FRAMES
/**
 * Enable logging of frame metadata.
 */
#define WS_CLIENT_LOG_FRAMES 0
#endif

#ifndef WS_CLIENT_LOG_COMPRESSION
/**
 * Enable logging of permessage-deflate compression related messages.
 */
#define WS_CLIENT_LOG_COMPRESSION 0
#endif
