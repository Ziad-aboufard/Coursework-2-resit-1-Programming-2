// client.cpp

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <mutex>

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method(); // SSLv23_method() for TLS 1.0-1.2 compatibility
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

bool send_credentials(SSL *ssl, const std::string& username, const std::string& password) {
    SSL_write(ssl, username.c_str(), username.size());
    SSL_write(ssl, password.c_str(), password.size());

    char buffer[512];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        std::cerr << "Error receiving authentication response\n";
        return false;
    }
    buffer[bytes_received] = '\0';
    std::cout << buffer << std::endl;

    return std::string(buffer) == "Authentication successful";
}

void display_incoming_messages(SSL *ssl) {
    char buffer[1024]; // Increased buffer size for encrypted messages
    while (true) {
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            std::cerr << "Error receiving message or connection closed\n";
            break;
        }

        buffer[bytes_received] = '\0';
        // Decrypt the received message (if needed)
        std::cout << "\nReceived encrypted message: " << buffer << std::endl;
        std::cout << "Enter recipient: ";
        std::cout.flush(); // Ensure the prompt is displayed immediately
    }
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();

    SSL *ssl;
    int server_socket;
    sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Unable to create socket\n";
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5678);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(server_socket, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "Unable to connect to server\n";
        close(server_socket);
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_socket);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server_socket);
        return 1;
    }

    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    if (!send_credentials(ssl, username, password)) {
        SSL_free(ssl);
        close(server_socket);
        return 1;
    }

    std::thread display_thread(display_incoming_messages, ssl);

    while (true) {
        std::string recipient, message;

        std::cout << "Enter recipient: ";
        std::getline(std::cin, recipient);

        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        std::string full_message = recipient + ":" + message;

        // Encrypt the message before sending
        SSL_write(ssl, full_message.c_str(), full_message.size());
    }

    display_thread.join();

    SSL_free(ssl);
    close(server_socket);
    cleanup_openssl();
    return 0;
}
