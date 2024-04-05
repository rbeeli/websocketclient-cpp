===============================================
C++ WebSocket client (``websocketclient-cpp``)
===============================================

.. table::
   :align: center

   +-----------------------------------------------------------------+--------------------------------------------------------+
   | .. image:: https://img.shields.io/badge/License-MIT-yellow.svg  | .. image:: https://img.shields.io/maintenance/yes/2024 |
   |    :target: ./LICENSE                                           |                                                        |
   +-----------------------------------------------------------------+--------------------------------------------------------+

A high-performance C++23 WebSocket client library with minimal dependencies.

- Full `RFC 6455 <https://www.rfc-editor.org/rfc/rfc6455.html>`_ compliance
- WebSocket Secure (WSS) support
- Passes all `Autobahn Testsuite <https://github.com/crossbario/autobahn-testsuite>`_ tests
- Compression support (permessage-deflate protocol extension, `RFC 7692 <https://www.rfc-editor.org/rfc/rfc7692.html>`_)
- Support for ``zlib-ng`` over ``zlib`` library for improved deflate performance on modern architectures
- Fast UTF-8 validation using SIMD (`simdutf <https://github.com/simdutf/simdutf>`_, optional)
- Fast payload masking using SIMD
- Does not throw exceptions (works with ``-fno-exceptions``)
- Few dependencies (STL, OpenSSL, zlib, simdutf)
- Blocking I/O support (built-in)
- Non-blocking I/O support using C++20 coroutines, e.g. using standalone ASIO
- No callback hell and easier object liftime management using C++20 coroutines
- Pluggable transport layer
- Pluggable logging
- **GCC** compiler support, C++23 required (TODO Clang)
- Tested on 64-bit **x86** and **ARM64** (**Ubuntu x86**, **MacOS M2 ARM64**) platforms (32-bit NOT supported)

.. pull-quote::
   [!WARNING]

    Despite being used in production, this library is still under development and the API may change.

----

.. contents:: Table of Contents

Dependencies
============

+---------------------------------------------------+-------------------------------------------------------------------------------------+----------+-----------------------------+
| Dependency                                        | Description                                                                         | Required | Switch                      |
+===================================================+=====================================================================================+==========+=============================+
| `simdutf <https://github.com/simdutf/simdutf>`_   | SIMD instructions based UTF-8 validator used for TEXT messages payload validation.  | Optional | ``WS_CLIENT_USE_SIMD_UTF8`` |
+---------------------------------------------------+-------------------------------------------------------------------------------------+----------+-----------------------------+
| `openssl 3+ <https://github.com/openssl/openssl>`_| WebSocket Secure (WSS) support.                                                     | Optional |                             |
+---------------------------------------------------+-------------------------------------------------------------------------------------+----------+-----------------------------+
| `zlib <https://github.com/madler/zlib>`_          | Message compression support through permessage-deflate extension.                   | Optional |                             |
+---------------------------------------------------+-------------------------------------------------------------------------------------+----------+-----------------------------+
| `zlib-ng <https://github.com/zlib-ng/zlib-ng>`_   | Faster alternative to ``zlib`` library with optimizations for modern CPUs.          | Optional | ``WS_CLIENT_USE_ZLIB_NG``   |
+---------------------------------------------------+-------------------------------------------------------------------------------------+----------+-----------------------------+

Transport layer
===============

The library is designed to be transport layer agnostic. It is up to the user to provide a transport layer implementation, which is responsible for reading and writing data to the network. The library supports both synchronous and asynchronous transport layers. Built-in blocking I/O transport layers are provided. Bindings for Standalone ASIO are also available.

Examples
========

Working examples can be found in the `examples <examples>`_ directory.

Logging
=======

By default, the library logs directly to ``std::clog``, hence there is no dependency to any logging library.

The default implementation allows to set the log level at compile-time, which can be used to filter log messages.

.. code-block:: cpp

    ConsoleLogger<LogLevel::I> logger;
    auto client = WebSocketClient(&logger, [...]);

In this example, only log messages with log level ``I`` (info) and higher will be printed.
The available log levels are:

.. code-block:: cpp

    enum class LogLevel : uint8_t
    {
        N = 0, // Disabled
        E = 1, // Error
        W = 2, // Warning
        I = 3, // Info
        D = 4  // Debug
    };


You can implement a custom logger like the following:

.. code-block:: cpp

    class CustomLogger
    {
    public:
        CustomLogger() noexcept = default;

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

Sometimes, changing the log-level will either show too many messages, or hide the ones of interest.
In order to filter for specific implementation details, the following macro-switches are available (``0`` = disabled, ``1`` = enabled):

.. code-block:: cpp

    #define WS_CLIENT_LOG_HANDSHAKE 0
    #define WS_CLIENT_LOG_MSG_PAYLOADS 0
    #define WS_CLIENT_LOG_MSG_SIZES 0
    #define WS_CLIENT_LOG_FRAMES 0
    #define WS_CLIENT_LOG_PING_PONG 0
    #define WS_CLIENT_LOG_COMPRESSION 0

By setting a variable to ``0`` = disabled (``1`` = enabled), the compiler will optimize out all logging code for maximum performance.

For example, the handshake log messages are useful to inspect the HTTP headers sent and received during the WebSocket handshake, e.g. negotiated parameters for the permessage-deflate compression extension.

Implementation details
======================

Template type parameters are supplemented by C++23 concepts, which are used to validate template parameters at compile-time.
Concepts have the advantage to formalize requirements for a template parameter, similar to interface definitions, and provide more meaningful error messages.

Multi-threading
---------------

This client implementation is not thread-aware and does not do any synchronization.
If used in a multi-threaded environment, synchronization needs to be ensured by the user.

Buffers and maximum message size
--------------------------------

The implementation does not allocate separate memory for each messages and/or frames.
``WebSocketClient`` maintains a configurable read buffer, which are reused for all messages and frames.
On a write operation, the message payload is directly written to the socket, without copying it to a separate buffer.

Additionally, if enabled, the ``PermessageDeflate`` compression extension maintains a compression and decompression buffer, which are used for all messages and frames.

This implies that the maximum message size is limited by the size of the read/write/compression buffers.
If exceeded, a ``BUFFER_ERROR`` error will be returned.

Message payload lifetime
------------------------

Received ``Message`` objects must be processed immediately after receiving them, otherwise the next message will overwrite the payload.

``Message`` objects must not be stored for later processing. If delayed processing is required, the payload must be copied away to a user-defined buffer.

Contribute
==========

Pull requests or issues are welcome, see `CONTRIBUTE.md <CONTRIBUTE.md>`_.

License
=======

Distributed under the MIT license, see `LICENSE <LICENSE>`_.
