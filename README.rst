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
- Unit tests using `Google Test <https://google.github.io/googletest/>`_
- Benchmarks using `Google Benchmark <https://google.github.io/googletest/>`_

.. pull-quote::
   [!WARNING]

   This library is not yet production ready. It is still under development and the API may change.

----

.. contents:: Table of Contents

Dependencies
------------

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
---------------

The library is designed to be transport layer agnostic. It is up to the user to provide a transport layer implementation, which is responsible for reading and writing data to the network. The library supports both synchronous and asynchronous transport layers. Built-in blocking I/O transport layers are provided. Bindings for Standalone ASIO are also available.

Examples
--------

.. code-block:: cpp

   TODO

Custom handshake headers
------------------------

.. code-block:: cpp

   TODO

Implementation details
----------------------

Template type parameters are supplemented by C++23 concepts, which are used to validate template parameters at compile-time. Concepts have the advantage to formalize requirements for a template parameter, similar to interface definitions, and provide more meaningful error messages.

Multi-threading
~~~~~~~~~~~~~~~

The client implementation is not aware of threads and does not use any locks. If used in a multi-threaded environment, synchronization needs to be ensured by the user of this library.

Buffers and maximum message size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The implementation does not allocate separate memory for each messages and/or frames.
``WebSocketClient`` maintains a configurable read buffer, which are reused for all messages and frames.
On a write operation, the message payload is directly written to the socket, without copying it to a separate buffer.

Additionally, if enabled, the ``PermessageDeflate`` compression extension maintains a compression and decompression buffer, which are used for all messages and frames.

This implies that the maximum message size is limited by the size of the read/write/compression buffers.
If exceeded, a ``BUFFER_ERROR`` error will be returned.

Message payload lifetime
~~~~~~~~~~~~~~~~~~~~~~~~

Received ``Message`` objects must be processed immediately after receiving them, otherwise the next message will overwrite the payload.

``Message`` objects must not be stored for later processing. If delayed processing is required, the payload must be copied away to a user-defined buffer.

Logging
-------

TODO

By default, the library logs directly to ``std::clog``, hence there is no dependency to any logging library. You can implement a custom logger like the following:

.. code-block:: cpp

    #include <iostream>

    TODO


All that is required is to override the macro ``WS_LOG_IMPL`` with your own implementation.

To disable logging completely, set ``WS_CLIENT_LOG_LEVEL`` to ``0``. In doing so, the compiler will optimize out all logging code for maximum performance.

.. code-block:: cpp

    #define WS_CLIENT_LOG_LEVEL 0

Alternatively, the log level can be set to a specific level. The available log levels are:

.. code-block:: cpp

    enum class LogLevel : uint8_t
    {
        N = 0, // Disabled
        E = 1, // Error
        W = 2, // Warning
        I = 3, // Info
        D = 4  // Debug
    };

Sometimes, changing the log-level will either show too many messages, or hide the ones of interest.

In order to filter for specific implementation details, the following macro-switches are available (``0`` = disabled, ``1`` = enabled):

.. code-block:: cpp

    #define WS_CLIENT_LOG_HANDSHAKE 1
    #define WS_CLIENT_LOG_MSG_PAYLOADS 1
    #define WS_CLIENT_LOG_MSG_SIZES 1
    #define WS_CLIENT_LOG_FRAMES 1
    #define WS_CLIENT_LOG_PING_PONG 1

For example, the handshake log messages are useful to inspect the HTTP headers sent and received during the WebSocket handshake, e.g. negotiated parameters for the permessage-deflate compression extension.

Contribute
----------

Pull requests or issues are welcome, see `CONTRIBUTE.md <CONTRIBUTE.md>`_.

License
-------

Distributed under the MIT license, see `LICENSE <LICENSE>`_.
