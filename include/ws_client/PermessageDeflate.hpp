#pragma once

#include <expected>
#include <iostream>
#include <sstream>
#include <charconv>
#include <cstdint>
#include <span>
#include <map>

#ifdef WS_CLIENT_USE_ZLIB_NG
#include <zlib-ng.h>
#define WS_CLIENT_USE_ZLIB_NG_BOOL true
#define z_stream zng_stream
#define inflateInit2(_strm, _windowBits) zng_inflateInit2(_strm, _windowBits)
#define inflate(_strm, __flush) zng_inflate(_strm, __flush)
#define inflateEnd(_strm) zng_inflateEnd(_strm)
#define inflateReset(_strm) zng_inflateReset(_strm)
#define deflateInit2(_strm, _level, _method, _windowBits, _memLevel, _strategy)                    \
    zng_deflateInit2(_strm, _level, _method, _windowBits, _memLevel, _strategy)
#define deflateEnd(_strm) zng_deflateEnd(_strm)
#define deflateReset(_strm) zng_deflateReset(_strm)
#define deflate(_strm, _flush) zng_deflate(_strm, _flush)
#else
#define WS_CLIENT_USE_ZLIB_NG_BOOL false
#include <zlib.h>
#endif

#include "ws_client/errors.hpp"
#include "ws_client/utils/string.hpp"
#include "ws_client/log.hpp"
#include "ws_client/HttpHeader.hpp"
#include "ws_client/Frame.hpp"
#include "ws_client/Buffer.hpp"

namespace ws_client
{
using std::string;
using std::byte;
using std::span;
using std::map;

/**
 * Permessage-deflate extension, as defined in RFC 7692.
 * 
 * https://datatracker.ietf.org/doc/rfc7692/
 */
template <typename TLogger>
struct PermessageDeflate
{
    static constexpr bool zlib_ng = WS_CLIENT_USE_ZLIB_NG_BOOL;
    static constexpr uint8_t default_client_max_window_bits = 15;
    static constexpr uint8_t default_server_max_window_bits = 15;

    TLogger* logger;

    /**
     * Maximum size of the server’s LZ77 sliding window in bits, between 8 and 15.
     * 0 = not set.
     * 
     * Default: 15
     */
    uint8_t server_max_window_bits{default_server_max_window_bits};

    /**
     * Maximum size of the client’s LZ77 sliding window in bits, between 8 and 15.
     * 0 = not set.
     * 
     * Default: 15
     */
    uint8_t client_max_window_bits{default_client_max_window_bits};

    /**
     * If true, the server will not reuse LZ77 contexts, and will compress all messages
     * independent of the previous message.
     * 
     * Default: false
     */
    bool server_no_context_takeover{false};

    /**
     * If true, the client will not reuse LZ77 contexts, and will compress all messages
     * independent of the previous message.
     * 
     * Default: false
     */
    bool client_no_context_takeover{false};

    /**
     * Maximum allowed size of decompression buffer.
     * 
     * Default: 100 KB
     */
    size_t decompress_buffer_size{100 * 1024};

    /**
     * Maximum allowed size of compression buffer.
     * 
     * Default: 100 KB
     */
    size_t compress_buffer_size{100 * 1024};

    /**
     * Decompression (deflate) memory level.
     * The trade-off is between memory usage and compression speed.
     * 
     * Valid values: 1-9
     * Default: 8 
     */
    int deflate_memory_level{8};

    /**
     * Compression (deflate) level.
     * The trade-off is between compression speed and compression ratio.
     * 
     * Valid values: 0-9
     * Default: zlib library default (Z_DEFAULT_COMPRESSION), currently 6.
     */
    int deflate_compression_level{Z_DEFAULT_COMPRESSION};


    /**
     * Process the HTTP response headers and adjust the configuration if needed.
     * The server might not respond with the exact configuration requested, so we need to
     * adjust the configuration accordingly.
     */
    [[nodiscard]] expected<bool, WSError> negotiate(const HttpResponseHeader& response)
    {
        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
            logger->template log<LogLevel::D>(
                this->zlib_ng ? "Using zlib-ng compression library"
                              : "Using standard zlib compression library"
            );
        }

        auto h_ext = response.fields.get_first("Sec-WebSocket-Extensions");
        if (h_ext == std::nullopt)
        {
            logger->template log<LogLevel::W>(
                "HTTP response without 'Sec-WebSocket-Extensions' header, disabling "
                "permessage-deflate extension."
            );
            return false;
        }

        map<string, string> extensions = parse_WebSocketExtensions(*h_ext);

        // verify permessage-deflate exists
        if (extensions.find("permessage-deflate") == extensions.end())
        {
            logger->template log<LogLevel::W>(
                "permessage-deflate extension not in 'Sec-WebSocket-Extensions' header, "
                "disabling extension."
            );
            return false;
        }

        WS_TRY(res1, this->negotiate_server_no_context_takeover(extensions));
        WS_TRY(res2, this->negotiate_client_no_context_takeover(extensions));
        WS_TRY(res3, this->negotiate_server_max_window_bits(extensions));
        WS_TRY(res4, this->negotiate_client_max_window_bits(extensions));

#if WS_CLIENT_LOG_HANDSHAKE == 1
        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
            logger->template log<LogLevel::D>(
                "Negotiated permessage-deflate parameters:\n"
                " - server_max_window_bits:      " +
                std::to_string(this->server_max_window_bits) +
                "\n"
                " - client_max_window_bits:      " +
                std::to_string(this->client_max_window_bits) +
                "\n"
                " - server_no_context_takeover:  " +
                std::to_string(this->server_no_context_takeover) +
                "\n"
                " - client_no_context_takeover:  " +
                std::to_string(this->client_no_context_takeover)
            );
        }
#endif

        return true;
    }

    [[nodiscard]] expected<void, WSError> negotiate_server_no_context_takeover(
        map<string, string>& extensions
    )
    {
        // verify/adjust server_no_context_takeover
        //
        //      Requested   Response    Result
        //      ---------   --------    ------
        //      False       False       False
        //      False       True        True
        //      True        False       True -> adjust configured value!
        //      True        True        True
        if (this->server_no_context_takeover)
        {
            if (extensions.find("server_no_context_takeover") == extensions.end())
            {
                this->server_no_context_takeover = false; // adjust configured value!

#if WS_CLIENT_LOG_HANDSHAKE == 1
                if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
                {
                    logger->template log<LogLevel::D>(
                        "server_no_context_takeover adjusted from " +
                        std::to_string(this->server_no_context_takeover) + " to 0"
                    );
                }
#endif
            }
        }
        else if (extensions.find("server_no_context_takeover") != extensions.end())
        {
#if WS_CLIENT_LOG_HANDSHAKE == 1
            if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
            {
                logger->template log<LogLevel::D>(
                    "server_no_context_takeover adjusted from " +
                    std::to_string(this->server_no_context_takeover) + " to 1"
                );
            }
#endif
            this->server_no_context_takeover = true;
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> negotiate_client_no_context_takeover(
        map<string, string>& extensions
    )
    {
        // verify/adjust client_no_context_takeover
        //
        //  Requested   Response    Result (client behavior)
        //  ---------   --------    -----------------------
        //  False       False       Client may use context takeover
        //  False       True        Client may use context takeover
        //  True        False       Client must not use context takeover
        //  True        True        Client must not use context takeover
        if (this->client_no_context_takeover)
        {
            // indepent of the response, the client must not use context takeover
        }
        else if (extensions.find("client_no_context_takeover") != extensions.end())
        {
#if WS_CLIENT_LOG_HANDSHAKE == 1
            if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
            {
                logger->template log<LogLevel::D>(
                    "client_no_context_takeover adjusted from " +
                    std::to_string(this->client_no_context_takeover) + " to 1"
                );
            }
#endif
            this->client_no_context_takeover = true;
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> negotiate_server_max_window_bits(
        map<string, string>& extensions
    )
    {
        // verify server_max_window_bits
        //
        //      Requested   Response    Result
        //      ---------   --------    ------
        //      None        None        None
        //      None        [8,15]      Use response value
        //      [8,15]      None        Use default value of 15
        //      [8,15]      8 ≤ M ≤ N   Use response value if M ≤ N, otherwise ERROR!
        if (this->server_max_window_bits > 0)
        {
            if (extensions.find("server_max_window_bits") == extensions.end())
            {
#if WS_CLIENT_LOG_HANDSHAKE == 1
                if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
                {
                    logger->template log<LogLevel::D>(
                        "server_max_window_bits=" + std::to_string(this->server_max_window_bits) +
                        " not acknowledged by server, use default value " +
                        std::to_string(default_server_max_window_bits)
                    );
                }
#endif
                this->server_max_window_bits = default_server_max_window_bits;
            }
            else
            {
                WS_TRY(res, parse_window_bits(extensions["server_max_window_bits"]));
                uint8_t res_value = *res;

                if (res_value < 8 || res_value > 15)
                {
                    return WS_ERROR(
                        protocol_error,
                        "Invalid server_max_window_bits value received. Expected: 8-15, got: " +
                            std::to_string(res_value),
                        close_code::not_set
                    );
                }

                if (res_value > this->server_max_window_bits)
                {
                    return WS_ERROR(
                        protocol_error,
                        "Received server_max_window_bits " + std::to_string(res_value) +
                            " greater than requested value of " +
                            std::to_string(this->server_max_window_bits),
                        close_code::not_set
                    );
                }

                if (this->server_max_window_bits != res_value)
                {
#if WS_CLIENT_LOG_HANDSHAKE == 1
                    if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
                    {
                        logger->template log<LogLevel::D>(
                            "server_max_window_bits adjusted from " +
                            std::to_string(this->server_max_window_bits) + " to " +
                            std::to_string(res_value)
                        );
                    }
#endif
                    this->server_max_window_bits = res_value;
                }
            }
        }
        else if (extensions.find("server_max_window_bits") != extensions.end())
        {
            WS_TRY(res, parse_window_bits(extensions["server_max_window_bits"]));
            uint8_t res_value = *res;

            if (res_value < 8 || res_value > 15)
            {
                return WS_ERROR(
                    protocol_error,
                    "Invalid server_max_window_bits value received. Expected: 8-15, got: " +
                        std::to_string(res_value),
                    close_code::not_set
                );
            }

            this->server_max_window_bits = res_value;

#if WS_CLIENT_LOG_HANDSHAKE == 1
            if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
            {
                logger->template log<LogLevel::D>(
                    "server_max_window_bits adjusted from " +
                    std::to_string(this->server_max_window_bits) + " to " +
                    std::to_string(res_value)
                );
            }
#endif
        }
        else
        {
            this->server_max_window_bits = default_server_max_window_bits;

#if WS_CLIENT_LOG_HANDSHAKE == 1
            if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
            {
                logger->template log<LogLevel::I>(
                    "Using default server_max_window_bits: " +
                    std::to_string(this->server_max_window_bits)
                );
            }
#endif
        }

        return {};
    }

    [[nodiscard]] expected<void, WSError> negotiate_client_max_window_bits(
        map<string, string>& extensions
    )
    {
        // verify client_max_window_bits
        //
        //      Requested   Response    Result
        //      ---------   --------    ------
        //      None        None        None
        //      None        [8,15]      ERROR!
        //      [8,15]      None        Use default value of 15
        //      [8,15]      8 ≤ M ≤ N   Use response value if M ≤ N, otherwise ERROR!
        if (this->client_max_window_bits > 0)
        {
            if (extensions.find("client_max_window_bits") == extensions.end())
            {
#if WS_CLIENT_LOG_HANDSHAKE == 1
                if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
                {
                    logger->template log<LogLevel::D>(
                        "client_max_window_bits=" + std::to_string(this->client_max_window_bits) +
                        " not acknowledged by server, use default value " +
                        std::to_string(default_client_max_window_bits)
                    );
                }
#endif

                this->client_max_window_bits = default_client_max_window_bits;
            }
            else
            {
                WS_TRY(res, parse_window_bits(extensions["client_max_window_bits"]));
                uint8_t res_value = *res;

                if (res_value < 8 || res_value > 15)
                {
                    return WS_ERROR(
                        protocol_error,
                        "Invalid client_max_window_bits value received. Expected: 8-15, got: " +
                            std::to_string(res_value),
                        close_code::not_set
                    );
                }

                if (res_value > this->client_max_window_bits)
                {
                    return WS_ERROR(
                        protocol_error,
                        "Received client_max_window_bits " + std::to_string(res_value) +
                            " greater than requested value of " +
                            std::to_string(this->client_max_window_bits),
                        close_code::not_set
                    );
                }

                if (this->client_max_window_bits != res_value)
                {
#if WS_CLIENT_LOG_HANDSHAKE == 1
                    if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
                    {
                        logger->template log<LogLevel::D>(
                            "client_max_window_bits adjusted from " +
                            std::to_string(this->client_max_window_bits) + " to " +
                            std::to_string(res_value)
                        );
                    }
#endif
                    this->client_max_window_bits = res_value;
                }
            }
        }
        else if (extensions.find("client_max_window_bits") != extensions.end())
        {
            string client_max_window_bits_str = extensions.find("client_max_window_bits")->second;

            int client_max_window_bits_parsed;
            auto const res = std::from_chars(
                client_max_window_bits_str.data(),
                client_max_window_bits_str.data() + client_max_window_bits_str.size(),
                client_max_window_bits_parsed
            );

            if (res.ec != std::errc{})
            {
                return WS_ERROR(
                    protocol_error,
                    "Failed to parse client_max_window_bits from server: " +
                        client_max_window_bits_str,
                    close_code::not_set
                );
            }

            if (client_max_window_bits_parsed < 8 || client_max_window_bits_parsed > 15)
            {
                return WS_ERROR(
                    protocol_error,
                    "Invalid client_max_window_bits value received. Expected: 8-15, got: " +
                        std::to_string(client_max_window_bits_parsed),
                    close_code::not_set
                );
            }

            this->client_max_window_bits = static_cast<uint8_t>(client_max_window_bits_parsed);
        }
        else
        {
            this->client_max_window_bits = default_client_max_window_bits;

#if WS_CLIENT_LOG_HANDSHAKE == 1
            if (logger->template is_enabled<LogLevel::I>()) [[unlikely]]
            {
                logger->template log<LogLevel::I>(
                    "Using default client_max_window_bits: " +
                    std::to_string(this->client_max_window_bits)
                );
            }
#endif
        }

        return {};
    }

    string get_Sec_WebSocket_Extensions_value() const
    {
        std::ostringstream stream;
        stream << "permessage-deflate";

        if (this->server_max_window_bits > 0)
            stream << "; server_max_window_bits=" << +this->server_max_window_bits;

        if (this->client_max_window_bits > 0)
            stream << "; client_max_window_bits=" << +this->client_max_window_bits;

        if (this->server_no_context_takeover)
            stream << "; server_no_context_takeover";

        if (this->client_no_context_takeover)
            stream << "; client_no_context_takeover";

        return stream.str();
    }

    map<string, string> parse_WebSocketExtensions(const string& header)
    {
        map<string, string> extensions;
        std::istringstream stream(header);
        string extension;

        while (std::getline(stream, extension, ';'))
        {
            extension.erase(
                std::remove_if(extension.begin(), extension.end(), ::isspace), extension.end()
            );

            std::istringstream extStream(extension);
            string key, value;
            if (std::getline(std::getline(extStream, key, '='), value))
            {
                key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
                value.erase(std::remove_if(value.begin(), value.end(), ::isspace), value.end());
                extensions[key] = value;
            }
            else
                extensions[extension] = "";
        }

        return extensions;
    }

    [[nodiscard]] expected<uint8_t, WSError> parse_window_bits(const string bits_string) const
    {
        int result;
        auto const res = std::from_chars(
            bits_string.data(), bits_string.data() + bits_string.size(), result
        );
        if (res.ec != std::errc{})
        {
            return WS_ERROR(
                protocol_error,
                "Invalid window bits value received. Expected: 8-15, got: " + bits_string,
                close_code::not_set
            );
        }
        return static_cast<uint8_t>(result);
    }
};

template <typename TLogger>
class PermessageDeflateContext
{
private:
    TLogger* logger_;
    PermessageDeflate<TLogger> permessage_deflate_;
    z_stream* istate_;
    z_stream* ostate_;

public:
    explicit PermessageDeflateContext(
        TLogger* logger, const PermessageDeflate<TLogger> permessage_deflate
    ) noexcept
        : logger_(logger), permessage_deflate_(std::move(permessage_deflate))
    {
    }

    ~PermessageDeflateContext() noexcept
    {
        if (istate_ != nullptr)
        {
            inflateEnd(istate_);
            deflateEnd(ostate_);

            delete istate_;
            delete ostate_;
        }
    }

    // disable copy
    PermessageDeflateContext(const PermessageDeflateContext&) = delete;
    PermessageDeflateContext& operator=(PermessageDeflateContext const&) = delete;

    // enable move
    PermessageDeflateContext(PermessageDeflateContext&& other) noexcept
        : logger_(other.logger_),
          permessage_deflate_(std::move(other.permessage_deflate_)),
          istate_(other.istate_),
          ostate_(other.ostate_)
    {
        other.istate_ = nullptr;
        other.ostate_ = nullptr;
    }
    PermessageDeflateContext& operator=(PermessageDeflateContext&& other) noexcept
    {
        if (this != &other)
        {
            logger_ = other.logger_;
            permessage_deflate_ = std::move(other.permessage_deflate_);
            istate_ = other.istate_;
            ostate_ = other.ostate_;

            other.istate_ = nullptr;
            other.ostate_ = nullptr;
        }
    }

    /**
     * Initialize the permessage-deflate context.
     * This is usually called after the WebSocket handshake is completed
     * by the client internally.
     */
    [[nodiscard]] expected<void, WSError> init() noexcept
    {
        // initialize zlib decompressor
        istate_ = new z_stream();
        istate_->zalloc = Z_NULL;
        istate_->zfree = Z_NULL;
        istate_->opaque = Z_NULL;
        istate_->avail_in = 0;
        istate_->next_in = Z_NULL;

        auto ret = inflateInit2(istate_, -1 * permessage_deflate_.server_max_window_bits);
        if (ret != Z_OK)
            return make_error("inflateInit2", istate_->msg);

        // initialize zlib compressor
        ostate_ = new z_stream();
        ostate_->zalloc = Z_NULL;
        ostate_->zfree = Z_NULL;
        ostate_->opaque = Z_NULL;
        ostate_->avail_in = 0;
        ostate_->next_in = Z_NULL;

        ret = deflateInit2(
            ostate_,
            permessage_deflate_.deflate_compression_level,
            Z_DEFLATED,
            -1 * permessage_deflate_.client_max_window_bits,
            permessage_deflate_.deflate_memory_level,
            Z_DEFAULT_STRATEGY
        );
        if (ret != Z_OK)
            return make_error("deflateInit2", ostate_->msg);

        return {};
    }

    [[nodiscard]] expected<size_t, WSError> decompress(span<byte> input, Buffer& output) noexcept
    {
        // set zlib input buffer to frame payload
        istate_->next_in = reinterpret_cast<Bytef*>(input.data());
        istate_->avail_in = static_cast<unsigned int>(input.size());

        size_t buffer_pos = output.size();
        size_t size = 0;
        do
        {
            // extend output buffer if required.
            // assumes average compression ratio of 5:1.
            // if more than 5x the input size is required, the buffer will be extended again.
            WS_TRY(alloc_res, output.append(std::max(64U, istate_->avail_in * 5)));
            span<byte> avail = *alloc_res;

            // set zlib output buffer
            istate_->next_out = reinterpret_cast<Bytef*>(avail.data());
            istate_->avail_out = static_cast<unsigned int>(avail.size());

            // decompress using zlib inflate
            int ret = inflate(istate_, Z_SYNC_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
                return make_error("inflate", istate_->msg);

            size += avail.size() - istate_->avail_out;
        } while (istate_->avail_out == 0);

#if WS_CLIENT_LOG_COMPRESSION == 1
        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
            logger->template log<LogLevel::D>(
                "compression ratio: " + std::to_string((double)size / input.size())
            );
        }
#endif

        // resize output buffer
        output.discard_end(output.size() - buffer_pos - size);

        if (permessage_deflate_.server_no_context_takeover)
        {
            // reset inflate state (discard LZ77 sliding window, no context takeover)
            if (Z_OK != inflateEnd(istate_))
                return make_error("inflateEnd", istate_->msg);

            if (Z_OK != inflateInit2(istate_, -1 * permessage_deflate_.server_max_window_bits))
                return make_error("inflateInit2", istate_->msg);
        }
        else
        {
            // reset inflate state (preserve LZ77 sliding window)
            if (Z_OK != inflateReset(istate_))
                return make_error("inflateReset", istate_->msg);
        }

        return size;
    }

    [[nodiscard]] expected<span<byte>, WSError> compress(span<byte> input, Buffer& output) noexcept
    {
        // handle empty payload case
        if (input.size() == 0) [[unlikely]]
        {
            constexpr byte buf[] = {
                byte(0x02), byte(0x00), byte(0x00), byte(0x00), byte(0xff), byte(0xff)
            };
            WS_TRYV(output.append(6));
            std::memcpy(output.data().data(), buf, sizeof(buf));
            return output.data().subspan(0, 6);
        }

        // set zlib input buffer to frame payload
        ostate_->next_in = reinterpret_cast<Bytef*>(input.data());
        ostate_->avail_in = static_cast<unsigned int>(input.size());

        // zlib flush mode (preserve LZ77 sliding window or not)
        int client_flush_mode = permessage_deflate_.client_no_context_takeover //
                                    ? Z_FULL_FLUSH
                                    : Z_SYNC_FLUSH;

        size_t size = 0;
        do
        {
            // extend output buffer if required, usually over-allocates.
            WS_TRY(alloc_res, output.append(std::max(64U, ostate_->avail_in)));
            span<byte> avail = *alloc_res;

            // set zlib output buffer
            ostate_->next_out = reinterpret_cast<Bytef*>(avail.data());
            ostate_->avail_out = static_cast<unsigned int>(avail.size());

            int ret = deflate(ostate_, client_flush_mode);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
                return make_error("deflate", ostate_->msg);

            size += avail.size() - ostate_->avail_out;
            output.discard_end(ostate_->avail_out);
        } while (ostate_->avail_out == 0);

#if WS_CLIENT_LOG_COMPRESSION == 1
        if (logger->template is_enabled<LogLevel::D>()) [[unlikely]]
        {
            logger->template log<LogLevel::D>(
                "compression ratio: " + std::to_string((double)input.size() / size)
            );
        }
#endif

        // reset deflate state depending on negotiated configuration
        if (permessage_deflate_.client_no_context_takeover)
        {
            if (Z_OK != deflateReset(ostate_))
                return make_error("deflateReset", ostate_->msg);
        }

        // remove trailer bytes (0x00 0x00 0xff 0xff)
        if (size >= 4)
            size -= 4;

        return output.data().subspan(0, size);
    }

    [[nodiscard]] static auto make_error(string_view desc, const char* msg) noexcept
    {
        std::ostringstream os;
        os << "zlib [" << desc << "] failed: " << (msg != NULL ? string(msg) : "N/A");
        return WS_ERROR(compression_error, os.str(), close_code::not_set);
    }
};
} // namespace ws_client
