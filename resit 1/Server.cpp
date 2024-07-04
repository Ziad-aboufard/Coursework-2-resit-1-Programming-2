// server.cpp

#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <mutex>
#include <vector>
#include <map>

// Simple user authentication data (username:password)
const char *credentials_file_path = "/C:\Users\Ziadg\Desktop\Cyber Sec. & Ethical Hack\Level 5\Semester 2\Programming and Algorithms 2\resit 1/credentials.txt";

void cleanup_openssl()
{
    EVP_cleanup();
    ERR_free_strings();
}

bool authenticate(const std::string &username, const std::string &password)
{
    std::ifstream credentials_file(credentials_file_path);
    if (!credentials_file.is_open())
    {
        std::cerr << "Failed to open credentials file\n";
        return false;
    }

    std::string stored_username, stored_password;
    while (credentials_file >> stored_username >> stored_password)
    {
        if (username == stored_username && password == stored_password)
        {
            credentials_file.close();
            return true;
        }
    }

    credentials_file.close();
    return false;
}

std::map<std::string, SSL *> client_map;
std::mutex client_map_mutex;

void handle_client(SSL *ssl)
{
    std::string username;
    std::string password;

    // Receive username
    char buffer[512];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0)
    {
        std::cerr << "Error receiving username\n";
        SSL_free(ssl);
        return;
    }
    buffer[bytes_received] = '\0';
    username = buffer;

    // Receive password
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0)
    {
        std::cerr << "Error receiving password\n";
        SSL_free(ssl);
        return;
    }
    buffer[bytes_received] = '\0';
    password = buffer;

    // Check authentication
    if (authenticate(username, password))
    {
        std::cout << "Authentication successful for user: " << username << std::endl;

        std::string auth_success = "Authentication successful";
        SSL_write(ssl, auth_success.c_str(), auth_success.size());

        // Add client to map
        std::lock_guard<std::mutex> lock(client_map_mutex);
        client_map[username] = ssl;
    }
    else
    {
        std::cout << "Authentication failed for user: " << username << std::endl;

        std::string auth_fail = "Authentication failed";
        SSL_write(ssl, auth_fail.c_str(), auth_fail.size());
        SSL_free(ssl);
        return;
    }

    while (true)
    {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0)
        {
            std::cerr << "Client disconnected or error occurred\n";
            break;
        }
        buffer[bytes_received] = '\0';

        // Decrypt the received message
        std::string message = buffer;
        // Process plaintext (e.g., extract recipient, message)
        size_t delimiter_pos = message.find(':');
        if (delimiter_pos == std::string::npos)
        {
            std::cerr << "Invalid message format\n";
            continue;
        }
        std::string recipient = message.substr(0, delimiter_pos);
        std::string msg_content = message.substr(delimiter_pos + 1);

        // Find recipient in map and send the message
        std::lock_guard<std::mutex> lock(client_map_mutex);
        auto it = client_map.find(recipient);
        if (it != client_map.end())
        {
            SSL *recipient_ssl = it->second;

            // Encrypt the message before sending
            SSL_write(recipient_ssl, msg_content.c_str(), msg_content.size());
        }
        else
        {
            std::cerr << "Recipient " << recipient << " not found\n";
        }
    }

    // Remove client from map
    std::lock_guard<std::mutex> lock(client_map_mutex);
    auto it = client_map.find(username);
    if (it != client_map.end())
    {
        client_map.erase(it);
    }

    SSL_free(ssl);
}

int main()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Set the paths to the certificate and key files
    const char *cert_path = "/C:\Users\Ziadg\Desktop\Cyber Sec. & Ethical Hack\Level 5\Semester 2\Programming and Algorithms 2\resit 1/server.crt";
    const char *key_path = "/C:\Users\Ziadg\Desktop\Cyber Sec. & Ethical Hack\Level 5\Semester 2\Programming and Algorithms 2\resit 1/server.key";

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        std::cerr << "Failed to create socket\n";
        SSL_CTX_free(ctx);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5678);

    if (bind(server_socket, (sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cerr << "Bind failed\n";
        SSL_CTX_free(ctx);
        return 1;
    }

    if (listen(server_socket, 5) == -1)
    {
        std::cerr << "Listen failed\n";
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "Server listening on port 5678\n";

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr *)&client_addr, &client_size);
        if (client_socket == -1)
        {
            std::cerr << "Accept failed\n";
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        std::cout << "Client connected: " << inet_ntoa(client_addr.sin_addr) << std::endl;
        std::thread(handle_client, ssl).detach();
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
