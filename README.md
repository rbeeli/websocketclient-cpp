# C++ WebSocket client (`websocketclient-cpp`)

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Maintenance](https://img.shields.io/maintenance/yes/2024)

A transport-agnostic, high-performance C++23 WebSocket client library with minimal dependencies.

- Full [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) compliance
- WebSocket Secure (WSS) support
- Compression support (permessage-deflate protocol extension, [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692.html))
- Support for `zlib-ng` over `zlib` library for improved deflate performance on modern architectures
- Fast UTF-8 validation using SIMD ([simdutf](https://github.com/simdutf/simdutf), optional)
- Fast payload masking using SIMD
- Does not throw exceptions (works with `-fno-exceptions`)
- No hidden networking control flow
  - User decides when and what to write as response to ping/close frames
- Few dependencies (STL, OpenSSL, zlib or zlib-ng, simdutf)
- Pluggable transport layer
  - Blocking I/O support (built-in)
  - Non-blocking I/O support using C++20 coroutines, e.g. using standalone ASIO
  - No callback hell and easier object liftime management using C++20 coroutines
- Pluggable logging
- **GCC** compiler support, C++23 required (TODO Clang)
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
| [simdutf](https://github.com/simdutf/simdutf)    | SIMD instructions based UTF-8 validator used for TEXT messages payload validation. | Optional |
| [openssl 3+](https://github.com/openssl/openssl) | WebSocket Secure (WSS) support.                                                    | If using WSS. |
| [zlib](https://github.com/madler/zlib)           | Message compression support through permessage-deflate extension.                  | If using compression (permessage-deflate). |
| [zlib-ng](https://github.com/zlib-ng/zlib-ng)    | Faster alternative to `zlib` library with optimizations for modern CPUs.           | If using compression (permessage-deflate), alternative to `zlib`. |

See the [examples](examples) directory for more information.

For configuration of dependencies, refer to the section [Configuration](#configuration).

## Examples

Working examples can be found in the [examples](examples) directory.
Examples exist for both built-in synchronous, and asynchronous (ASIO) transport mechanisms.


## Configuration

### Compile-time configuration

The following compile-time configuration switches can be set:

| Option                       | Values      | Description |
| -------------------------    | ----------- | ------------------------------------------------------------------ |
| `WS_CLIENT_USE_SIMD_UTF8`    | `1` or `0`  | Enable/disable SIMD instructions based UTF-8 validator for TEXT messages payload validation. |
| `WS_CLIENT_USE_ZLIB_NG`      | `1` or `0`  | Enable/disable `zlib-ng` instead of `zlib` library for permessage-deflate compression. |
| `WS_CLIENT_VALIDATE_UTF8`    | `1` or `0`  | Enable/disable UTF-8 validation for TEXT messages payload. |
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

Output files are generated in the `out` directory.

```bash
cmake --preset dev_install
cmake --build --preset dev_install
cmake --install out/dev_install --config Release
```

## Transport layer

The library is designed to be transport layer agnostic.
The library supports both synchronous and asynchronous transport layers.
Built-in blocking I/O transport layers are provided, incl. bindings for C++20 coroutines using standalone ASIO (no Boost dependency).

The user can provide their own transport layer implementation if needed.

- Synchronous example: [examples/ex_echo_sync.cpp](examples/ex_echo_sync.cpp)
- ASIO example: [examples/ex_echo_asio.cpp](examples/ex_echo_asio.cpp)

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

You can implement a custom logger like the following:

```cpp
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

```cpp
#define WS_CLIENT_LOG_HANDSHAKE 0
#define WS_CLIENT_LOG_MSG_PAYLOADS 0
#define WS_CLIENT_LOG_MSG_SIZES 0
#define WS_CLIENT_LOG_FRAMES 0
#define WS_CLIENT_LOG_COMPRESSION 0
```

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

### Buffers and maximum message size

The implementation does not allocate separate memory for each message and/or frames.
`WebSocketClient` maintains a configurable read buffer, which are reused for all messages and frames.
On a write operation, the message payload is directly written to the socket, without copying it to a separate buffer.

Additionally, if enabled, the `PermessageDeflate` compression extension maintains a compression and decompression buffer, which are used for all messages and frames.

This implies that the maximum message size is limited by the size of the read/write/compression buffers.
If exceeded, a `BUFFER_ERROR` error will be returned.

### Message payload lifetime

Received `Message` objects must be processed immediately after receiving them, otherwise the next message will overwrite the payload.

`Message` objects must not be stored for later processing. If delayed processing is required, the payload must be copied away to a user-defined buffer.

## Contribute

Pull requests or issues are welcome, see [CONTRIBUTE.md](CONTRIBUTE.md).

## Autobahn Testsuite report

The library passes all tests of the Autobahn Testsuite, see [Autobahn Testsuite report](https://rbeeli.github.io/websocketclient-cpp/tests/autobahn/reports_summary/index.html).

## License

Distributed under the MIT license, see [LICENSE](LICENSE).
