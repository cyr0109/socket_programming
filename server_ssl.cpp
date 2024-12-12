#include <iostream>
#include <string>
#include <map>
#include <mutex>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct User {
    std::string username;
    std::string ip_address;
    int port_number;
    int actual_port_number;
    double account_balance;
    bool is_logged;
    std::string public_key; // 新增欄位
};

class Server {
public:
    Server(int server_port);
    void start();
private:
    int socket_fd;
    struct sockaddr_in server_addr;
    std::map<std::string, User> user_map;
    std::mutex user_map_mutex;
    SSL_CTX *ssl_ctx;

    static void* client_thread(void* arg);
    void handle_client(int client_socket, struct sockaddr_in client_addr, SSL* ssl);
    void handle_registration(const std::string& message, int client_socket, SSL* ssl);
    void handle_login(const std::string& message, int client_socket, struct sockaddr_in client_addr, SSL* ssl);
    void handle_list(int client_socket, const sockaddr_in& client_addr, SSL* ssl);
    void handle_micropayment(const std::string& message, int client_socket, SSL* ssl);
};

struct ThreadArgs {
    Server* server_instance;
    int client_socket;
    struct sockaddr_in client_addr;
    SSL* ssl;
};

Server::Server(int server_port) {
    // Initialize SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == nullptr) {
        std::cerr << "SSL_CTX_new failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Optionally, load certificates and private keys if required
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "SSL_CTX_use_certificate_file failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "SSL_CTX_use_PrivateKey_file failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Optional: Check if the private key matches the certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        std::cerr << "Private key does not match the public certificate!" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    socket_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        std::cerr << "Fail to create a socket." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = PF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);

    if (bind(socket_fd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind socket failed!");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(socket_fd, 5) == -1) {
        std::cerr << "Socket " << socket_fd << " listen failed!" << std::endl;
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is ready, listening on port " << server_port << "..." << std::endl;
}

void Server::handle_registration(const std::string& message, int client_socket, SSL* ssl) {
    size_t first_delim = message.find('#', 9); // 找到 username 的結尾位置
    size_t second_delim = message.find('#', first_delim + 1); // 找到 public_key 的結尾位置

    std::string username = message.substr(9, first_delim - 9);
    std::string public_key = message.substr(first_delim + 1, second_delim - first_delim - 1);

    user_map_mutex.lock();
    if (user_map.find(username) != user_map.end()) {
        user_map_mutex.unlock();
        std::string response = "210 FAIL\r\n";
        SSL_write(ssl, response.c_str(), response.size());
    } else {
        User new_user = {username, "", 0, 0, 10000, false, public_key};
        user_map[username] = new_user;
        user_map_mutex.unlock();
        std::string response = "100 OK\r\n";
        SSL_write(ssl, response.c_str(), response.size());
    }
    // std::cout << username << " has registered with public key: " << public_key << std::endl;
}


void Server::handle_login(const std::string& message, int client_socket, struct sockaddr_in client_addr, SSL* ssl) {
    // Expected message format: "username#port"
    size_t delimiter_pos = message.find('#');

    std::string username = message.substr(0, delimiter_pos);
    int port_number = std::stoi(message.substr(delimiter_pos + 1));
    std::string ip_address = inet_ntoa(client_addr.sin_addr);

    user_map_mutex.lock();
    if (user_map.find(username) == user_map.end()) { // Username is not registered
        user_map_mutex.unlock();
        std::string response = "220 AUTH_FAIL\r\n";
        SSL_write(ssl, response.c_str(), response.size());
    } else if (user_map[username].is_logged) { // User is already logged in
        user_map_mutex.unlock();
        std::string response = "230 ALREADY_LOGGED_IN\r\n";
        SSL_write(ssl, response.c_str(), response.size());
    } else {
        user_map[username].ip_address = ip_address;
        user_map[username].port_number = port_number;
        user_map[username].actual_port_number = ntohs(client_addr.sin_port);
        user_map[username].is_logged = true;
        user_map_mutex.unlock();

        std::ostringstream response_stream;

        // Add account balance and public key
        response_stream << user_map[username].account_balance << "\r\n"
                        << "public key\r\n";

        int user_online = 0;
        // Add number of accounts online
        for (const auto& pair : user_map) {
            const User& user = pair.second;
            if (user.is_logged) {
                user_online++; 
            }
        }
        response_stream << user_online << "\r\n";

        // Add user account details (username, IP, and port)
        for (const auto& pair : user_map) {
            const User& user = pair.second;
            if (user.is_logged) {
                response_stream << user.username << "#" << user.ip_address << "#" 
                            << user.port_number << "\r\n";
            }
        }

        // Convert to string and send the response
        std::string response = response_stream.str();
        SSL_write(ssl, response.c_str(), response.size());
        std::cout << username << " has logged" << std::endl;
    }
}

void Server::handle_list(int client_socket, const sockaddr_in& client_addr, SSL* ssl) {
    // Get the client's IP address and port
    std::string client_ip = inet_ntoa(client_addr.sin_addr);
    int actual_client_port = ntohs(client_addr.sin_port);
    // Find the user based on IP and port
    std::string username;
    for (const auto& pair : user_map) {
        const User& user = pair.second;
        if (user.ip_address == client_ip && user.actual_port_number == actual_client_port) {
            username = user.username;
            break;
        }
    }

    // If the user is not found, send an error response
    if (username.empty()) {
        std::string error_message = "Please login first\r\n";
        SSL_write(ssl, error_message.c_str(), error_message.size());
        return;
    }

    // Prepare the response
    std::ostringstream response_stream;

    // Add account balance and public key
    const User& current_user = user_map[username];
    response_stream << current_user.account_balance << "\r\n"
                    << current_user.public_key << "\r\n"; // 插入真正的公鑰

    int user_online = 0;
    // Add number of accounts online
    for (const auto& pair : user_map) {
        const User& user = pair.second;
        if (user.is_logged) {
            user_online++; 
        }
    }
    response_stream << user_online << "\r\n";

    // Add user account details (username, IP, and port)
    for (const auto& pair : user_map) {
        const User& user = pair.second;
        if (user.is_logged) {
            response_stream << user.username << "#" << user.ip_address << "#" 
                            << user.port_number << "\r\n";
        }
    }

    // Convert to string and send the response
    std::string response = response_stream.str();
    SSL_write(ssl, response.c_str(), response.size());
    std::cout << response;
}


void Server::handle_micropayment(const std::string& message, int client_socket, SSL* ssl) {
    std::cout << "handling micropayment" << std::endl;
    std::istringstream ss(message);
    std::string sender, payee, amount_str;
    getline(ss, sender, '#');
    getline(ss, amount_str, '#');
    getline(ss, payee, '#');
    double amount = std::stod(amount_str);

    // Find sender and payee in user_map
    user_map_mutex.lock();
    if (user_map.find(sender) == user_map.end() || user_map.find(payee) == user_map.end()) {
        user_map_mutex.unlock();
        std::string response = "220 AUTH_FAIL\r\n";
        SSL_write(ssl, response.c_str(), response.size());
        return;
    }

    User& sender_user = user_map[sender];
    User& payee_user = user_map[payee];

    // Check if sender has sufficient balance
    if (sender_user.account_balance < amount) {
        user_map_mutex.unlock();
        std::string response = "230 INSUFFICIENT_FUNDS\r\n";
        SSL_write(ssl, response.c_str(), response.size());
        return;
    }

    // Perform transaction
    sender_user.account_balance -= amount;
    payee_user.account_balance += amount;
    user_map_mutex.unlock();
    std::cout << sender << " has transferred " << amount_str << " to " << payee << std::endl;
}




void Server::handle_client(int client_socket, struct sockaddr_in client_addr, SSL* ssl) {
    char buf[1024] = {0};

    while (SSL_read(ssl, buf, sizeof(buf)) > 0) {
        std::string message(buf);
        if (message.find("REGISTER#") == 0) {
            handle_registration(message, client_socket, ssl);
        } else if (std::count(message.begin(), message.end(), '#') == 1) {
            handle_login(message, client_socket, client_addr, ssl);
        } else if (std::count(message.begin(), message.end(), '#') == 2) {
            handle_micropayment(message, client_socket, ssl);
        } else if (message == "List") {
            handle_list(client_socket, client_addr, ssl);
        } else if (message == "Exit") {
            std::string response = "Bye\r\n";
            SSL_write(ssl, response.c_str(), response.size());
            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            int actual_client_port = ntohs(client_addr.sin_port);
            // Find the user based on IP and port
            std::string username;
            for (const auto& pair : user_map) {
                const User& user = pair.second;
                if (user.ip_address == client_ip && user.actual_port_number == actual_client_port) {
                    username = user.username;
                    user_map[username].is_logged = false;
                    break;
                }
            }
            break;
        }
        memset(buf, 0, sizeof(buf));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
}

void* Server::client_thread(void* arg) {
    ThreadArgs* args = static_cast<ThreadArgs*>(arg);
    args->server_instance->handle_client(args->client_socket, args->client_addr, args->ssl);
    delete args;
    return nullptr;
}

void Server::start() {
    while (true) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        client_socket = accept(socket_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed!");
            continue;
        }

        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        pthread_t tid;
        ThreadArgs* args = new ThreadArgs;
        args->server_instance = this;
        args->client_socket = client_socket;
        args->client_addr = client_addr;
        args->ssl = ssl;
        pthread_create(&tid, nullptr, &Server::client_thread, args);
        pthread_detach(tid);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " [port]" << std::endl;
        return EXIT_FAILURE;
    }

    int server_port = std::stoi(argv[1]);
    Server server(server_port);
    server.start();

    return 0;
}
