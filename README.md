# C++ WebSocket client (`websocketclient-cpp`)

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Maintenance](https://img.shields.io/maintenance/yes/2024)

A transport-agnostic, high-performance, header-only C++23 WebSocket client library with minimal dependencies.

- Full [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) compliance
- WebSocket Secure (WSS) support
- Compression support (`permessage-deflate` protocol extension, [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692.html))
- Support for `zlib-ng` over `zlib` library for improved (de-)compression performance on modern architectures
- Fast, optional UTF-8 text frame validation using SIMD ([simdutf](https://github.com/simdutf/simdutf))
- Fast payload masking using SIMD
- Does not throw exceptions (works with `-fno-exceptions`)
- No hidden networking control flow
  - User decides when and what to write as response to ping/close frames
  - No hidden synchronization needed
- Pre-allocate message payload buffer once and reuse it for all messages
- Timeout parameter for all network operations
- Few dependencies (STL, [OpenSSL](https://github.com/openssl/openssl), [zlib](https://github.com/madler/zlib) or [zlib-ng](https://github.com/zlib-ng/zlib-ng), [simdutf](https://github.com/simdutf/simdutf))
- Pluggable transport layers
  - Blocking I/O support (built-in based on POSIX)
  - Non-blocking async I/O support based on C++20 coroutines, e.g. using [ASIO](https://github.com/chriskohlhoff/asio)
  - Ability to provide custom transport layer
  - No callback hell and easier object liftime management when using C++20 coroutines
- Pluggable logging (optional)
- **GCC 12+** and **Clang 19+** compiler support
- Tested on 64-bit **x86** and **ARM64** (**Ubuntu x86**, **MacOS M2 ARM64**) platforms (32-bit NOT supported)
- Passes all [Autobahn Testsuite](https://github.com/crossbario/autobahn-testsuite) tests

> **NOTE:**
> Despite being used in production, this library is still under development and the API may change.

## Table of Contents

- [Dependencies](#dependencies)
- [Examples](#examples)
- [Transport layer](#transport-layer)
- [Logging](#logging)
- [Implementation details](#implementation-details)
- [Contribute](#contribute)
- [License](#license)

## Dependencies

| Dependency                                       | Description                                                                        | Required |
| ------------------------------------------------ | ---------------------------------------------------------------------------------- | -------- |
| [simdutf](https://github.com/simdutf/simdutf)    | SIMD instructions based UTF-8 validator used for text messages payload validation. | Optional |
| [openssl 3](https://github.com/openssl/openssl) | WebSocket Secure (WSS) support.                                                    | If using WSS. |
| [zlib](https://github.com/madler/zlib)           | Message compression support through permessage-deflate extension.                  | If using compression (permessage-deflate). |
| [zlib-ng](https://github.com/zlib-ng/zlib-ng)    | Faster alternative to `zlib` library with optimizations for modern CPUs.           | If using compression (permessage-deflate), alternative to `zlib`. |

See the [examples](examples) directory for more information.

For configuration of dependencies, refer to the section [Configuration](#configuration).

## Examples

Working examples can be found in the [examples](examples) directory.
Examples exist for both built-in blocking I/O based on POSIX, and asynchronous I/O using ASIO.

- Blocking I/O examples: [examples/builtin/](examples/builtin/)
- Async I/O ASIO examples: [examples/asio/](examples/asio/)

### Setting custom HTTP headers

Custom HTTP headers, e.g. for authentication, can be set on the `Handshake` instance as follows:

```cpp
handshake.get_request_header().fields.set("X-Custom-Header", "Custom-Value");
```

## Configuration

### Compile-time configuration

The following compile-time configuration switches can be set:

| Option                       | Values      | Description |
| -------------------------    | ----------- | ------------------------------------------------------------------ |
| `WS_CLIENT_USE_SIMD_UTF8`    | `1` or `0`  | Enable/disable SIMD instructions based UTF-8 validator for text messages payload validation. |
| `WS_CLIENT_USE_ZLIB_NG`      | `1` or `0`  | Enable/disable `zlib-ng` instead of `zlib` library for permessage-deflate compression. |
| `WS_CLIENT_VALIDATE_UTF8`    | `1` or `0`  | Enable/disable UTF-8 validation for text messages payload. |
| `WS_CLIENT_LOG_HANDSHAKE`    | `1` or `0`  | Enable/disable handshake log messages. |
| `WS_CLIENT_LOG_MSG_PAYLOADS` | `1` or `0`  | Enable/disable message payload log messages. |
| `WS_CLIENT_LOG_MSG_SIZES`    | `1` or `0`  | Enable/disable message size log messages. |
| `WS_CLIENT_LOG_FRAMES`       | `1` or `0`  | Enable/disable frame log messages. |
| `WS_CLIENT_LOG_COMPRESSION`  | `1` or `0`  | Enable/disable compression log messages. |

Example:

```cmake
target_compile_definitions(my_binary PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_VALIDATE_UTF8=1 # Enable utf-8 validation
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=0
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=0
    WS_CLIENT_LOG_COMPRESSION=0
)
```

### CMake options

The following CMake options can be set in order to build examples, tests and/or benchmarks:

| Option                       | Description |
| ---------------------------- | ----------- |
| `WS_CLIENT_BUILD_EXAMPLES`   | Build examples in the `examples` directory. |
| `WS_CLIENT_BUILD_TESTS`      | Build unit tests in the `test` directory. |
| `WS_CLIENT_BUILD_BENCH`      | Build performance benchmarks in the `bench` directory. |
| `WS_CLIENT_BUILD_SCRATCH`    | Build scratch examples in the `scratch` directory. |

## Build / Install

Output files are generated in the `build` directory.

### GCC

```bash
cmake --preset gcc_dev_install
cmake --build --preset gcc_dev_install
cmake --install build/gcc/dev_install --config Release
```

### Clang

```bash
cmake --preset clang_dev_install
cmake --build --preset clang_dev_install
cmake --install build/clang/dev_install --config Release
```

## Transport layer

The library is designed to be transport layer agnostic, which is one of its unique features compared to other WebSocket libraries.
The library supports both blocking and non-blocking, asynchronous transport layers via `WebSocketClient`, or `WebSocketClientAsync` respectively.

Blocking I/O is provided by the built-in transport layers`TcpSocket` and `OpenSslSocket`, which uses POSIX I/O functions and OpenSSL for TLS connections.

An async I/O socket implementation is provided using the ASIO library and C++20 coroutines, see `AsioSocket` class.

The user can provide their own transport layer (socket) implementation if needed.
All that is required is to implement the following functions in a custom socket class:

```cpp
read_some(buffer, timeout);
write_some(buffer, timeout);
shutdown(timeout);
close();
```

For details, see the concepts `HasSocketOperations` in [HasSocketOperations.hpp](include/ws_client/transport/HasSocketOperations.hpp), or `HasSocketOperationsAsync` in [HasSocketOperationsAsync.hpp](include/ws_client/transport/HasSocketOperationsAsync.hpp) respectively.

## Logging

By default, the library logs directly to `std::clog`, hence there is no dependency to any logging library.

The default implementation allows to set the log level at compile-time, which can be used to filter log messages.

```cpp
ConsoleLogger<LogLevel::I> logger;
auto client = WebSocketClient(&logger, [...]);
```

In this example, only log messages with log level `I` (info) and higher will be printed.
The available log levels are:

```cpp
enum class LogLevel : uint8_t
{
    N = 0, // Disabled
    E = 1, // Error
    W = 2, // Warning
    I = 3, // Info
    D = 4  // Debug
};
```

You can implement a custom logger like the following. It logs all messages to `std::cout`:

```cpp
/**
 * Custom logger implementation.
 * Logs all messages to `std::cout`.
 */
struct CustomLogger
{
    /**
     * Check if the logger is enabled for the given log level.
     */
    template <LogLevel level>
    constexpr bool is_enabled() const noexcept
    {
        return true;
    }

    /**
     * Log a message with the given log level.
     */
    template <LogLevel level>
    constexpr void log(
        std::string_view message, const std::source_location loc = std::source_location::current()
    ) noexcept
    {
        std::cout << "CustomLogger: " << loc.file_name() << ":" << loc.line() << " " << message
                  << std::endl;
    }
};
```

Sometimes, changing the log-level will either show too many messages, or hide the ones of interest.
In order to filter for specific implementation details, the following compile definitions are available (`0` = disabled, `1` = enabled):

| Option                       | Values      | Description |
| -------------------------    | ----------- | ------------------------------------------------------------------ |
| `WS_CLIENT_LOG_HANDSHAKE`    | `1` or `0`  | Enable/disable handshake log messages. |
| `WS_CLIENT_LOG_MSG_PAYLOADS` | `1` or `0`  | Enable/disable message payload log messages. |
| `WS_CLIENT_LOG_MSG_SIZES`    | `1` or `0`  | Enable/disable message size log messages. |
| `WS_CLIENT_LOG_FRAMES`       | `1` or `0`  | Enable/disable frame log messages. |
| `WS_CLIENT_LOG_COMPRESSION`  | `1` or `0`  | Enable/disable compression log messages. |

By setting a variable to `0` = disabled (`1` = enabled), the compiler will optimize out all logging code for maximum performance.

For example, the handshake log messages are useful to inspect the HTTP headers sent and received during the WebSocket handshake.
Among others, the negotiated parameters for the permessage-deflate compression extension can be inspected this way.

Alternatively, use CMake's compile definition function `target_compile_definitions` to set the log levels (see above).

## Implementation details

Template type parameters are supplemented by C++23 concepts, which are used to validate template parameters at compile-time.
Concepts have the advantage to formalize requirements for a template parameter, similar to interface definitions, and provide more meaningful error messages.

### Multi-threading

This client implementation is not thread-aware, hence does not employ any synchronization primitives.
If used in a multi-threaded environment, synchronization needs to be handled by the user.

The control frames *ping*, *pong* and *close* are returned to the client in the same order as they are received.
The user is responsible for sending the corresponding pong or close frame in response.
By returning those frames to the user, the library enables the user to decide when and what to write as response, and does not hide any networking control flow, which would require synchronization.

### Timeouts

All network operations have a timeout parameter to limit the time spent on a single operation,
thus avoiding blocking the application indefinitely.

This includes the following functions in `WebSocketClient` and `WebSocketClientAsync`:

* `handshake`
* `wait_message`
* `read_message`
* `send_message`
* `send_pong_frame`
* `close`

### Buffers and maximum message size

The implementation does not allocate separate memory for each message and/or frames.
The user can supply the read buffer for messages as first argument to the `read_message` function.

On a write operation, the message payload is directly written to the socket, without copying it into a separate buffer.

Additionally, if enabled, the `permessage-deflate` compression extension maintains a compression and decompression buffer internally, which are used for all messages and frames.
The respective buffer size limits can be configured in the `PermessageDeflate` struct:

```cpp
struct PermessageDeflate
{
    [...]
    size_t decompress_buffer_size{100 * 1024}; // 100 KiB
    size_t compress_buffer_size{100 * 1024}; // 100 KiB
};
```

The initial size, and the maximum buffer size are set at the creation of a `Buffer` instance:

```cpp
// create buffer with initial size of 4 KiB, and maximum size of 1 MiB
Buffer::create(4096, 1024 * 1024);
```

The initial size is allocated directly.
Operations that need more buffer memory up to the maximum size lead to on-demand allocations by extending the buffer memory dynamically.
If any buffer limit would be exceeded by an operation, a `buffer_error` error will be returned.

### Message payload lifetime

Received `Message` objects must be processed immediately after receiving them, otherwise, the next message will overwrite the payload since all message objects share the same buffer.

`Message` objects must not be stored for later processing.
If deferred processing is required, the payload must be copied away to a user-defined buffer.

## Contribute

Pull requests or issues are welcome, see [CONTRIBUTE.md](CONTRIBUTE.md).

## Autobahn Testsuite report

The library passes all tests of the Autobahn Testsuite, see [Autobahn Testsuite report](https://rbeeli.github.io/websocketclient-cpp/tests/autobahn/reports_summary/index.html).

## License

Distributed under the MIT license, see [LICENSE](LICENSE).
