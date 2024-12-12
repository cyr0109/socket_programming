#include <iostream>
#include <string>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h> // For pthread_create
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct thread_args {
    int socket_fd;
    int peer_server_socket_fd;
    SSL* ssl;
};

class ClientP2P {
public:
    ClientP2P(const std::string& server_ip, int port);
    void connect_to_server();
    void send_message();
    void receive_message();
    void close_socket();
    void show_menu();
    void get_command();
    void register_to_server();
    void login();
    void list();
    void exit_to_server();
    std::string get_msg_sent() const; // Add this getter function
    SSL_CTX* ssl_ctx;
    SSL* ssl;
private:
    std::string server_ip;
    int port;
    int user_port;
    int peer_port;
    int socket_fd;
    int peer_server_socket_fd;
    int amount;
    struct sockaddr_in server_addr;
    struct sockaddr_in peer_addr;
    struct sockaddr_in user_addr;
    std::string user_ip;
    std::string peer_ip;
    std::string peer_name;
    std::string msg_sent;
    std::string msg_recv;
    std::string user_account_name;
    std::string public_key;
};

ClientP2P::ClientP2P(const std::string& server_ip, int port) {
    // OpenSSL 初始化
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = PF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or address not supported\n";
        exit(EXIT_FAILURE);
    }
    user_ip = server_ip;
}

void ClientP2P::connect_to_server() {
    socket_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        std::cerr << "Socket creation error\n";
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, socket_fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "Error: Unable to get server's certificate.\n";
        exit(EXIT_FAILURE);
    }
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        std::cerr << "Error: Unable to extract public key from certificate.\n";
        X509_free(cert); // 記得釋放憑證
        exit(EXIT_FAILURE);
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bio, pubkey)) {
        char* pem_key = nullptr;
        size_t pem_key_len = BIO_get_mem_data(bio, &pem_key);
        std::cout << "Public Key:\n" << std::string(pem_key, pem_key_len) << "\n";
    }
    // 獲取 BIO 內的資料
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Failed to get public key data from BIO");
    }

    std::string pubkey_string(data, len); // 將 BIO 內的資料轉換為字串
    public_key = pubkey_string;
    BIO_free(bio);
    EVP_PKEY_free(pubkey);
    X509_free(cert);

    std::cout << "Connected to server securely.\n";
}

void ClientP2P::send_message() {
    if (SSL_write(ssl, msg_sent.c_str(), msg_sent.length()) <= 0) {
        std::cout << "Send Message failed\n";
        return;
    }
    std::cout << "Message sent securely.\n";
}

void ClientP2P::receive_message() {
    char buffer[1024] = {0};
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        std::cout << "Server (secure): " << buffer << "\n";
    } else {
        std::cerr << "Error receiving message.\n";
    }
    msg_recv = buffer;
    std::cout << "the message from server is: " << msg_recv <<std::endl;
}

void ClientP2P::close_socket() {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(socket_fd);
    SSL_CTX_free(ssl_ctx);
}

void ClientP2P::show_menu() {
    std::cout << "Commands:" << std::endl;
    std::cout << "------------------" << std::endl;
    std::cout << "Register" << std::endl;
    std::cout << "Login" << std::endl;
    std::cout << "List" << std::endl;
    std::cout << "Transaction" << std::endl;
    std::cout << "Exit" << std::endl;
    std::cout << "------------------" << std::endl;
}

void ClientP2P::get_command() {
    std::cout << "Enter command to send (or 'Exit' to quit):" << std::endl;
    std::string message;
    std::getline(std::cin, message);
    // std::cout << "message " << message << " is received" << std::endl;
    if (message == "Register") {
        std::cout << "Please enter your user account name" << std::endl;
        std::getline(std::cin, user_account_name);
        this->register_to_server();
        std::cout << "You have registered in the server using name " << user_account_name << std::endl;
    }
    if (message == "Login") {
        std::cout << "Please enter your user account name" << std::endl;
        std::getline(std::cin, user_account_name);
        std::cout << "Please enter your port" << std::endl;
        std::cin >> user_port;
        std::cin.ignore();  // Clear the input
        this->login();
        std::cout << "You have logged into the server using name " << user_account_name << " and using port "<< user_port<< std::endl;
    }
    if (message == "List") {
        this->list();
    }
    if (message == "Transaction") {
        std::cout << "Please enter the peer's name" << std::endl;
        std::getline(std::cin, peer_name);
        std::cout << "Please enter the amount" << std::endl;
        std::cin >> amount;
        std::cin.ignore();  // Clear the input
        this->list();
        // std::cout << "msg_recv" << msg_recv << std::endl;
        std::istringstream stream(msg_recv);  // Use stringstream to read the input as if it's a stream of lines
    
        std::string line;
        int line_number = 0;
        std::string third_line;

        // Read lines one by one
        while (std::getline(stream, line)) {
            line_number++;
            if (line_number == 12) {
                std::cout << "line is " <<line << std::endl;
                third_line = line;  // Store the third line
                break;  // Stop once we find the third line
            }
        }
        int number = std::stoi(third_line); 
        for (int i=0;i<number;i++) {
            std::getline(stream, line);
            // Find the position of the first # character
            size_t pos1 = line.find('#');
            // Find the position of the second # character
            size_t pos2 = line.find('#', pos1 + 1);
            
            // Extract substrings based on positions
            std::string temp_peer_name = line.substr(0, pos1);  // AA
            std::string temp_peer_ip = line.substr(pos1 + 1, pos2 - pos1 - 1);  // 127.0.0.1
            std::string temp_peer_port = line.substr(pos2 + 1);  // 1111
            if (temp_peer_name == peer_name){
                peer_name = temp_peer_name;
                peer_ip = temp_peer_ip;
                peer_port = std::atoi(temp_peer_port.c_str());
            }
        }

        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = PF_INET;
        peer_addr.sin_port = htons(peer_port);
        peer_addr.sin_addr.s_addr = inet_addr(peer_ip.c_str());
        int peer_client_socket_fd = socket(PF_INET, SOCK_STREAM, 0);

        if (connect(peer_client_socket_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
            std::cerr << "Connection failed\n";
            exit(EXIT_FAILURE);
        } 
        std::cout << "connet peer successful" << std::endl;
        msg_sent = user_account_name + '#' + std::to_string(amount) + '#' + peer_name;
        if (send(peer_client_socket_fd, msg_sent.c_str(), msg_sent.length(), 0) < 0) {
            std::cout << "Send Message failed\n";
            return;
        } 
        std::cout << "Message sent.\n";
        // 關閉 socket，並檢查是否關閉成功
        if (close(peer_client_socket_fd) < 0) {
            perror("close socket failed!");
        }
        std::cout <<"Transfer Ok!" <<std::endl;
    }
    if (message == "Exit") {
        this->exit_to_server();
    }
}

std::string ClientP2P::get_msg_sent() const {
    return msg_sent; // Return the last sent message
}
void ClientP2P::register_to_server() {
    msg_sent = "REGISTER#" + user_account_name + "#" + public_key;
    this->send_message();
    this->receive_message();
}

void receiving(int peer_server_socket_fd, int socket_fd, SSL* ssl) {
    char buffer[1024] = {0};
    if (peer_server_socket_fd < 0) {
        perror("Invalid peer server socket descriptor");
        return;
    }

    while (true) {
        int reply_sockfd;
        struct sockaddr_in clientAddr;
        socklen_t client_len = sizeof(clientAddr);

        // 从 complete connection queue 中取出已连接的 socket
        reply_sockfd = accept(peer_server_socket_fd, (struct sockaddr *)&clientAddr, &client_len);
        if (reply_sockfd < 0) {
            perror("accept failed!");
            continue; // Skip to the next loop iteration
        }
        
        printf("Accept connection request from [%s:%d]\n", 
                inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        
        // 不断接收 client 数据
        while (true) {
            int bytes_read = recv(reply_sockfd, buffer, sizeof(buffer), 0);
            if (bytes_read < 0) {
                perror("recv failed!");
                break; // Exit the loop on error
            } 
            if (bytes_read == 0) {
                printf("Connection closed by client [%s:%d]\n", 
                        inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
                break; // Connection was closed by the client
            }

            // Show the received message
            buffer[bytes_read] = '\0'; // Ensure null-termination
            printf("Received message from [%s:%d]: %s\n", 
                    inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), buffer);

            std::string msg(buffer, bytes_read); // Create string with the exact length of the received data

            if (SSL_write(ssl, msg.c_str(), msg.length()) <= 0) {
                std::cout << "Send Message failed\n";
                ERR_print_errors_fp(stderr);  // Check detailed OpenSSL error
                return;
            }
            std::cout << "Message sent securely.\n";


            // Clear the message buffer
            memset(buffer, 0, sizeof(buffer));
        }

        // Close the reply socket
        if (close(reply_sockfd) < 0) {
            perror("close socket failed!");
        }
    }
}

void *receive_thread(void *args) {
    thread_args *t_args = (thread_args *)args;
    int ps_fd = t_args->peer_server_socket_fd;
    int s_fd = t_args->socket_fd;
    SSL* ssl = t_args->ssl;
    while (1) {
        receiving(ps_fd, s_fd, ssl);
    }
    delete t_args;

}

void ClientP2P::login() {
    msg_sent = user_account_name + "#" + std::to_string(user_port);
    this->send_message();
    this->receive_message();
    peer_server_socket_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (peer_server_socket_fd < 0) {
        std::cerr << "Socket creation failed!\n";
        exit(EXIT_FAILURE);
    }
    // 建立一個 sockaddr_in 結構，存著 user 的相關資料
    user_addr.sin_family = PF_INET;
    user_addr.sin_addr.s_addr = inet_addr(user_ip.c_str());
    user_addr.sin_port = htons(user_port);

    // 綁定 socket 到指定的 IP 和端口
    if (bind(peer_server_socket_fd, (struct sockaddr *)&user_addr, sizeof(user_addr)) < 0) {
        perror("Bind socket failed!");
        close(peer_server_socket_fd);  // 確保關閉 socket
        exit(1);
    }

    // 準備接受連線
    if (listen(peer_server_socket_fd, 5) == -1) {
        std::cout << "socket " << peer_server_socket_fd << " listen failed!" << std::endl;
        close(peer_server_socket_fd);
        exit(1);
    }
    pthread_t tid;
    thread_args* args = new thread_args();
    args->socket_fd = socket_fd;
    args->peer_server_socket_fd = peer_server_socket_fd;
    args->ssl = ssl;
    if (pthread_create(&tid, NULL, receive_thread, args) != 0) {
        perror("Failed to create thread");
        exit(EXIT_FAILURE);
    }

}

void ClientP2P::list() {
    msg_sent = "List";
    this->send_message();
    this->receive_message();
}

void ClientP2P::exit_to_server() {
    msg_sent = "Exit";
    this->send_message();
    this->receive_message();
}
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " [server_ip] [port]\n";
        return EXIT_FAILURE;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);

    ClientP2P client(server_ip, port);

    client.connect_to_server();

    while (true) {
        client.show_menu();
        client.get_command();
        if (client.get_msg_sent() == "Exit") {
            break;
        }
    }

    
    return 0;
}
