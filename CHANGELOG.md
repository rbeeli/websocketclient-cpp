# Changelog

All notable changes to this project will be documented in this file.

## [0.7.7] - 2026-11-19

### Fixed

- permessage-deflate: valid messages rejected because output space was over-reserved; messages larger than `compress_buffer_size` could not be sent compressed, and poorly compressible received messages failed well below the message buffer limit

## [0.7.6] - 2026-11-19

### Fixed

- Size overflow in `Buffer::append`, allowing a heap overflow from huge frame payload lengths when the message buffer has no size limit
- Stack overflow in the built-in TCP/TLS sockets for socket fd numbers >= `FD_SETSIZE` (1024), by using `poll` instead of `select`

## [0.7.5] - 2026-11-19

### Fixed

- Heap buffer overflow in `read_until` when the HTTP response terminator spans two socket reads
- permessage-deflate: messages after a server message ending with a BFINAL block were decoded as empty
- permessage-deflate: sending an empty message corrupted the server's decompression stream
- Completed messages reported as timeout when the deadline expired during the last read; read state is now reset on errors
- `Sec-WebSocket-Key` used only 8 random bytes out of 16

## [0.7.4] - 2026-11-19

### Fixed

- Payload masking of buffers not aligned to 4 bytes: the SSE2, NEON and 64-bit chunk paths used the unrotated masking key, corrupting sent frames ([#14](https://github.com/rbeeli/websocketclient-cpp/pull/14))

## [0.7.3] - 2026-08-15

### Added

- Repository-owned GCC and Clang CI with formatting, standalone-header, sanitizer, no-exception, API-instantiation, and installed-package checks

### Changed

- Improved CMake package metadata and propagated the C++23 and zlib requirements to consumers
- Pinned vcpkg dependencies to a reproducible baseline
- Made test and benchmark dependencies opt-in vcpkg features
- Updated Clang presets to use libc++ consistently
- Changed OpenSSL cipher and TLS version accessors to return `std::expected`
- Stopped installing the unfinished Coroio transport adapter

### Fixed

- Shared error-category and OpenSSL callback state across translation units
- Move support for WebSocket clients with move-only sockets and masking-key generators
- Preservation of custom handshake request headers when moving a handshake
- Compilation of previously uninstantiated OpenSSL accessors
- Rejection of empty URL hosts and partially parsed or out-of-range numeric fields
- Validation of WebSocket upgrade headers and URL authority edge cases
- Standalone compilation of public headers

## [0.7.2] - 2026-08-15

### Changed

- Check for a 64-bit architecture without relying on a declaration of `size_t`

## [0.7.1] - 2025-07-13

### Changed

- Hardened and fixed regression in `CircularBuffer` when buffer full

## [0.7] - 2025-07-12

### Removed

- Full circle: Remove explicit cancellation token parameters introduced in 0.6
  - Parameter removed from `WebSocketClientAsync`, `BufferedSocketAsync`, `ISocketAsync`, `HasSocketOperationsAsync`, `AsioSocket`
  - Built-in default cancellation of couroutines sufficient, see updated example in [examples/asio/ex_cancel_asio.cpp](./examples/asio/ex_cancel_asio.cpp)

## [0.6] - 2025-07-07

### Added

- Made async read/write operations cancellable by introducting a "cancellation slot" parameter
- Cancellation support implemented in `WebSocketClientAsync`, `BufferedSocketAsync`, `ISocketAsync`, `HasSocketOperationsAsync`, `AsioSocket`
- New error code `WSErrorCode::operation_cancelled = 11`
- ASIO cancellation example in [examples/asio/ex_cancel_asio.cpp](./examples/asio/ex_cancel_asio.cpp)

## [0.5] - 2025-06-20

### Changed

- Refactored `OpenSslContext`, changed SSL security defaults

## [0.4] - 2025-06-20

### Added

- New method `std::expected<bool, WSError> can_read()` in `WebSocketClientAsync`, `ISocketAsync`, `BufferedSocketAsync`, and `AsioSocket`

### Changed

- Removed all `using`s of `std` types within `ws_client` namespace, now fully qualified use everywhere
- Improved error handling and messages for SSL and sys calls
  - SSL error queue always cleared before SSL calls

### Fixed

- Error in macro `WS_ERROR` if used outside of `ws_client` namespace due to unqualified use of `WSError` and `WSErrorCode` if no `using namespace ws_client` at call site was present
- Fix examples/tests where ASIO SSL hostname verification fails by adding call to `SSL_set_tlsext_host_name`

## [0.3] - 2024-10-13

### Added

- This changelog file
- New `Makefile` with commands `autobahn-docker`, `dev-install`, `test-close`

### Changed

- During tear-down of websocket client, skip SSL and TCP shutdown (directly close) if websocket client is in faulty state.
  This is to prevent the client from hanging/reaching timeout, and is closer to the behaviour the RFC spec mandates.
- Added parameter `bool fail_connection` to socket API `close` and `shutdown` methods.
  The parameter should be set to `true` if the client and/or connection is in a faulty state.
  On shutdown/close, the client will skip SSL and TCP shutdown and directly close the connection since it's likely that the peer will not respond.
- Removed `dev_install.sh` script (moved to `Makefile`)
- Better error message printing in examples
- Log alert `close_notify` in `OpenSslSocket` as warning instead of error

### Fixed

- `to_string` for `ws_client::close_code` also maps `not_set`
