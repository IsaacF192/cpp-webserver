#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

const int PORT = 8080;
const std::string ROOT_DIR = "./www";

std::string get_http_response(const std::string& path) {
    std::string full_path = ROOT_DIR + path;

    // Default to index.html if path is "/"
    if (path == "/") {
        full_path = ROOT_DIR + "/index.html";
    }

    std::ifstream file(full_path);
    if (!file) {
        std::string not_found =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<h1>404 Not Found</h1>";
        return not_found;
    }

    std::stringstream buffer;
    buffer << file.rdbuf(); // read the whole file into buffer
    std::string body = buffer.str();

    std::stringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: text/html\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "\r\n";
    response << body;

    return response.str();
}

std::string parse_request_path(const std::string& request) {
    std::istringstream stream(request);
    std::string method, path, version;
    stream >> method >> path >> version;

    if (method != "GET") {
        return "/"; // just serve index.html for non-GET (we’ll improve this later)
    }

    return path;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
        client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        char buffer[4096] = {0};
        read(client_fd, buffer, sizeof(buffer));
        std::string request(buffer);
        std::cout << "Request:\n" << request << std::endl;

        std::string path = parse_request_path(request);
        std::string response = get_http_response(path);

        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
