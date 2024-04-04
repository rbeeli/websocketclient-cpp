#include <chrono>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h> // For gethostbyname

#define HOST_NAME "www.random.org"
#define HOST_PORT 443
#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"

int main()
{
    int sockfd;
    struct sockaddr_in server_addr;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    // Initialize WolfSSL
    wolfSSL_Init();

    // wolfSSL_Debugging_ON();

    // Create and setup WOLFSSL_CTX
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == nullptr)
    {
        std::cerr << "ERROR: failed to create WOLFSSL_CTX" << std::endl;
        return -1;
    }

    // Load default CA certificates
    if (wolfSSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL) !=
        SSL_SUCCESS)
    {
        std::cerr << "ERROR: failed to load verify locations" << std::endl;
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "ERROR: failed to create socket" << std::endl;
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // resolve the hostname to an IP address
    struct hostent* host = gethostbyname(HOST_NAME);
    if (host == nullptr)
    {
        std::cerr << "ERROR: failed to resolve hostname" << std::endl;
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    server_addr.sin_port = htons(HOST_PORT);

    // connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("ERROR: connect failed"); // More detailed error message
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // create a WOLFSSL object
    ssl = wolfSSL_new(ctx);
    if (ssl == nullptr)
    {
        std::cerr << "ERROR: failed to create WOLFSSL object" << std::endl;
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // associate the socket with the WOLFSSL object
    wolfSSL_set_fd(ssl, sockfd);

    // enable certificate verification
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    // set default cipher list to use
    wolfSSL_set_cipher_list(ssl, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");

    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

    // enable hostname verification
    if (wolfSSL_check_domain_name(ssl, HOST_NAME) != SSL_SUCCESS)
    {
        std::cerr << "ERROR: failed to set domain name" << std::endl;
        wolfSSL_free(ssl);
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // perform the SSL handshake
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        std::cerr << "ERROR: failed to perform SSL handshake" << std::endl;
        wolfSSL_free(ssl);
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Step 1: verify a server certificate was presented during the negotiation
    WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ssl);
    if (cert)
    {
        if (wolfSSL_X509_check_host(cert, HOST_NAME, strlen(HOST_NAME), 0, NULL) != SSL_SUCCESS)
        {
            std::cerr << "ERROR: failed to verify hostname" << std::endl;
            wolfSSL_free(ssl);
            close(sockfd);
            wolfSSL_CTX_free(ctx);
            return -1;
        }
        else
        {
            std::cout << "Hostname verified" << std::endl;
        }
        wolfSSL_FreeX509(cert);
    }

    // Step 2: verify the result of chain verification
    if (wolfSSL_get_verify_result(ssl) == X509_V_OK)
    {
        // Verification successful
        std::cout << "Certificate chain verified" << std::endl;
    }
    else
    {
        // Verification failed
        std::cerr << "ERROR: failed to verify certificate chain" << std::endl;
        wolfSSL_free(ssl);
        close(sockfd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    std::cout << "Connected and Handshaked with SSL server" << std::endl;


    // Construct the HTTP request
    std::string httpRequest = "GET " HOST_RESOURCE " HTTP/1.1\r\n"
                              "Host: " HOST_NAME "\r\n"
                              "Connection: close\r\n\r\n";

    // Send the HTTP request
    auto writeResult =
        wolfSSL_write(ssl, httpRequest.c_str(), static_cast<int>(httpRequest.length()));
    if (writeResult <= 0)
    {
        // Error handling
        int writeErr = wolfSSL_get_error(ssl, writeResult);
        std::cerr << "ERROR: failed to write, error code: " << writeErr << std::endl;
        // Handle the error (e.g., close connection and clean up)
    }
    else
    {
        std::cout << "HTTP request sent" << std::endl;
    }

    auto t = std::chrono::system_clock::now();

    // Reading the response in a loop
    const int readBufferSize = 4096;
    char readBuffer[readBufferSize];
    int bytesRead;
    do
    {
        bytesRead = wolfSSL_read(ssl, readBuffer, sizeof(readBuffer) - 1);
        if (bytesRead > 0) [[likely]]
        {
            std::cout << std::string(readBuffer, bytesRead) << std::endl;
        }
        else if (bytesRead < 0) [[unlikely]]
        {
            int readErr = wolfSSL_get_error(ssl, bytesRead);
            std::cerr << "ERROR: failed to read, error code: " << readErr << std::endl;
            break;
        }
    } while (bytesRead > 0);

    auto t2 = std::chrono::system_clock::now();
    std::cout << "Response read in " << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t).count() << " us" << std::endl;

    if (bytesRead == 0)
        std::cout << "Connection closed by peer" << std::endl;

    // Cleanup and close connection
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
