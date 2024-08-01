#pragma once

#ifndef WS_CLIENT_VALIDATE_UTF8
/**
 * Enables UTF-8 validation of text messages, see RFC 6455, section 5.6.
 * 
 * If disabled, does not validate text message payloads and close error messages.
 * Disable for improved performance and lower CPU load.
 * Recommended to enable during development and debugging.
 * 
 * Default: 1 (enabled)
 */
#define WS_CLIENT_VALIDATE_UTF8 1
#endif

#ifndef WS_CLIENT_LOG_HANDSHAKE
/**
 * Enable logging of handshake / negotiation messages and HTTP headers.
 * 
 * Default: 1 (enabled)
 */
#define WS_CLIENT_LOG_HANDSHAKE 1
#endif

#ifndef WS_CLIENT_LOG_MSG_PAYLOADS
/**
 * Enable logging of message payloads as strings.
 * 
 * Default: 0 (disabled)
 */
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#endif

#ifndef WS_CLIENT_LOG_MSG_SIZES
/**
 * Enable logging of message sizes without payload.
 * WS_CLIENT_LOG_MSG_PAYLOADS has higher priority.
 * 
 * Default: 1 (enabled)
 */
#define WS_CLIENT_LOG_MSG_SIZES 1
#endif

#ifndef WS_CLIENT_LOG_FRAMES
/**
 * Enable logging of frame metadata.
 * 
 * Default: 0 (disabled)
 */
#define WS_CLIENT_LOG_FRAMES 0
#endif

#ifndef WS_CLIENT_LOG_COMPRESSION
/**
 * Enable logging of permessage-deflate compression related messages.
 * 
 * Default: 0 (disabled)
 */
#define WS_CLIENT_LOG_COMPRESSION 0
#endif
