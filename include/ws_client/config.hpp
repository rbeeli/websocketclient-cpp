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

#ifndef WS_CLIENT_LOG_DNS
/**
 * Log level for DNS name resolution logging.
 * Topic: `LogTopic::DNS`
 * Default: 3 (INFO)
 */
#define WS_CLIENT_LOG_DNS 3
#endif

#ifndef WS_CLIENT_LOG_TCP
/**
 * Log level for TCP layer logging.
 * Topic: `LogTopic::TCP`
 * Default: 3 (INFO)
 */
#define WS_CLIENT_LOG_TCP 3
#endif

#ifndef WS_CLIENT_LOG_SSL
/**
 * Log level for SSL layer logging.
 * Topic: `LogTopic::SSL`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_SSL 2
#endif

#ifndef WS_CLIENT_LOG_HANDSHAKE
/**
 * Log level for handshake / negotiation messages and HTTP headers.
 * Topic: `LogTopic::Handshake`
 * Default: 3 (INFO)
 */
#define WS_CLIENT_LOG_HANDSHAKE 3
#endif

#ifndef WS_CLIENT_LOG_COMPRESSION
/**
 * Log level for permessage-deflate and zlib compression related messages.
 * Topic: `LogTopic::Compression`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_COMPRESSION 2
#endif

#ifndef WS_CLIENT_LOG_SEND_FRAME
/**
 * Log level for outgoing frame metadata logging.
 * Topic: `LogTopic::SendFrame`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_SEND_FRAME 2
#endif

#ifndef WS_CLIENT_LOG_SEND_FRAME_PAYLOAD
/**
 * Log level for outgoing message payloads.
 * Topic: `LogTopic::SendFramePayload`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_SEND_FRAME_PAYLOAD 2
#endif

#ifndef WS_CLIENT_LOG_RECV_FRAME
/**
 * Log level for incoming frame metadata logging.
 * Topic: `LogTopic::RecvFrame`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_RECV_FRAME 2
#endif

#ifndef WS_CLIENT_LOG_RECV_FRAME_PAYLOAD
/**
 * Log level for incoming message payloads.
 * Topic: `LogTopic::RecvFramePayload`
 * Default: 2 (WARN)
 */
#define WS_CLIENT_LOG_RECV_FRAME_PAYLOAD 2
#endif

#ifndef WS_CLIENT_LOG_USER
/**
 * Log level for user-supplied log messages.
 * The websocketclient library does not use this log topic.
 * Topic: `LogTopic::User`
 * Default: 3 (INFO)
 */
#define WS_CLIENT_LOG_USER 3
#endif
