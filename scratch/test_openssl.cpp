// https://wiki.openssl.org/index.php/SSL/TLS_Client

#include <iostream>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define HOST_NAME "www.random.org"
#define HOST_PORT "443"
#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"


int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    // For error codes, see http://www.openssl.org/docs/apps/verify.html
    // https://stackoverflow.com/questions/42272164/make-openssl-accept-expired-certificates

    int err = X509_STORE_CTX_get_error(x509_ctx);

    if (preverify == 0)
    {
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if (err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if (err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }

    if (err == X509_V_OK)
        return 1;

    return preverify;
}


[[noreturn]] static void ssl_error()
{
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    long len = BIO_get_mem_data(bio, &buf);
    if (len <= 0)
    {
        std::cerr << "SSL error: unknown" << std::endl;
        exit(1);
    }
    std::string ret(buf, static_cast<size_t>(len));
    BIO_free(bio);
    std::cerr << "SSL error: " << ret << std::endl;
    exit(1);
}

int main()
{
    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL* ssl = NULL;

    const SSL_METHOD* method = TLS_client_method();
    if (method == NULL)
        ssl_error();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        ssl_error();

    // register verify callback
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    // set verify depth
    // SSL_CTX_set_verify_depth(ctx, 4);

    // disable SSLv2 and SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    res = SSL_CTX_set_default_verify_paths(ctx);
    // res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
    if (res != 1)
        ssl_error();

    web = BIO_new_ssl_connect(ctx);
    if (web == NULL)
        ssl_error();

    res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
    if (res != 1)
        ssl_error();

    BIO_get_ssl(web, &ssl);
    if (ssl == NULL)
        ssl_error();

    // enable certificate verification
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    // set cipher list to use
    const char PREFERRED_CIPHERS[] = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if (res != 1)
        ssl_error();

    // set hostname
    res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
    if (res != 1)
        ssl_error();

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!(NULL != out))
        ssl_error();

    res = BIO_do_connect(web);
    if (res != 1)
        ssl_error();

    res = BIO_do_handshake(web);
    if (res != 1)
        ssl_error();

    // Step 1: verify a server certificate was presented during the negotiation
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        std::string hostname = HOST_NAME;
        if (X509_check_host(cert, hostname.c_str(), hostname.size(), 0, nullptr) != 1)
        {
            fprintf(stderr, "Certificate verification error: Hostname mismatch\n");
            exit(1);
        }

        X509_free(cert);
    }
    if (NULL == cert)
        ssl_error();

    // Step 2: verify the result of chain verification.
    // Verification performed according to RFC 4158.
    res = SSL_get_verify_result(ssl);
    if (res != X509_V_OK)
        ssl_error();

    BIO_puts(web,
             "GET " HOST_RESOURCE " HTTP/1.1\r\n"
             "Host: " HOST_NAME "\r\n"
             "Connection: close\r\n\r\n");
    BIO_puts(out, "\n");

    auto t = std::chrono::system_clock::now();

    int len = 0;
    bool should_retry = false;
    do
    {
        char buff[1536] = {};
        len = BIO_read(web, buff, sizeof(buff));

        if (len > 0)
        {
            int write_len = 0;
            int total_written = 0;

            while (total_written < len)
            {
                write_len = BIO_write(out, buff + total_written, len - total_written);
                if (write_len <= 0)
                {
                    // If BIO_write should be retried
                    if (BIO_should_retry(out))
                        continue; // Retry writing the remaining part of the buffer

                    std::cerr << "Error: BIO_write failed." << std::endl;
                    return -1; // Exit on non-retryable error
                }
                
                total_written += write_len;
            }
        }
        else if (len < 0)
        {
            // Check if BIO_read should be retried
            if (!BIO_should_retry(web))
            {
                std::cerr << "Error: BIO_read failed." << std::endl;
                return -1; // Exit on non-retryable error
            }
        }

        // Reset the retry flag for the next iteration
        should_retry = BIO_should_retry(web);

    } while (len > 0 || should_retry);

    auto t2 = std::chrono::system_clock::now();
    std::cout << "Response read in " << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t).count() << " us" << std::endl;

    // Check if the connection was closed properly or ended due to an error
    if (len == 0)
        std::cout << "Info: Connection closed successfully." << std::endl;
    else
        std::cerr << "Error: Connection ended with an error." << std::endl;

    if (out)
        BIO_free(out);

    if (web != NULL)
        BIO_free_all(web);

    if (NULL != ctx)
        SSL_CTX_free(ctx);

    return 0;
}
