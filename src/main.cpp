#include <iostream>       // for std::cout, std::cerr
#include <fstream>        // for file reading (serving HTML files)
#include <sstream>        // for string streams (building HTTP responses)
#include <string>         // for std::string
#include <cstring>        // for memset and C-string functions
#include <unistd.h>       // for close(), read(), write()
#include <netinet/in.h>   // for sockaddr_in, socket functions
#include <sys/socket.h>   // for socket(), bind(), listen(), accept()

const int PORT = 8080;                      // The port number the server will listen on
const std::string ROOT_DIR = "./www";       // Root folder to serve files from

// This function builds and returns the full HTTP response based on the requested path
std::string get_http_response(const std::string& path) {
    std::string full_path = ROOT_DIR + path; // Construct full path to requested file

    // If root path is requested, serve index.html by default
    if (path == "/") {
        full_path = ROOT_DIR + "/index.html";
    }

    std::ifstream file(full_path);  // Open the requested file
    if (!file) {
        // File doesn't exist — return 404 response
        std::string not_found =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<h1>404 Not Found</h1>";
        return not_found;
    }

    // File found — read it into a buffer
    std::stringstream buffer;
    buffer << file.rdbuf();            // Read entire file contents into buffer
    std::string body = buffer.str();   // Convert buffer to string

    // Build full HTTP response string
    std::stringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: text/html\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "\r\n";                // Blank line between headers and body
    response << body;

    return response.str();             // Return the full response string
}

// Parses the first line of the HTTP request to extract the path (e.g. "/about.html")
std::string parse_request_path(const std::string& request, std::string& method, std::string& body) {
    std::istringstream stream(request);
    std::string line;

    // First line looks like: POST /submit HTTP/1.1
    stream >> method;

    std::string path;
    stream >> path;

    // The request body comes after the empty line ("\r\n\r\n")
    size_t pos = request.find("\r\n\r\n");
    if (pos != std::string::npos) {
        body = request.substr(pos + 4); // skip past the blank line
    }

    return path;                      // Return the requested path
}

int main() {
    int server_fd, client_fd;               // File descriptors for server and client sockets
    struct sockaddr_in address;             // Struct for server address info
    socklen_t addrlen = sizeof(address);    // Size of the address struct

    // Create the socket: AF_INET = IPv4, SOCK_STREAM = TCP, 0 = default protocol
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");            // Print error if socket creation fails
        return 1;
    }

    // Fill in server address information
    address.sin_family = AF_INET;           // IPv4
    address.sin_addr.s_addr = INADDR_ANY;   // Bind to all network interfaces
    address.sin_port = htons(PORT);         // Convert port to network byte order

    // Bind the socket to the specified IP and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    // Start listening for connections (max 10 in queue)
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Main server loop — accepts and handles client connections one at a time
    while (true) {
        // Accept an incoming client connection
        client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        if (client_fd < 0) {
            perror("accept failed");         // Print error but keep server running
            continue;
        }

        // Buffer to hold the client's request
        char buffer[4096] = {0};             // 4KB buffer, zero-initialized

        // Read the request from the client socket into buffer
        read(client_fd, buffer, sizeof(buffer));

        std::string request(buffer);         // Convert buffer into std::string for easier handling
        std::cout << "Request:\n" << request << std::endl;

        // Parse the request path from the request
        std::string method, body;
std::string path = parse_request_path(request, method, body);
std::string response;

if (method == "GET") {
    response = get_http_response(path);
    
    } else if (method == "POST" && path == "/submit") 
    
    {
    // Save form submission to a file
    std::ofstream file("submissions.txt", std::ios::app);
    if (file) {
        file << body << "\n---\n";
    }

    response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<h1>Thanks for your submission!</h1>";
        } else {
    response =
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<h1>400 Bad Request</h1>";
        
        }
        // Send the response back to the client
        send(client_fd, response.c_str(), response.size(), 0);

        // Close the connection to the client
        close(client_fd);
    }

    // Clean up the server socket (technically unreachable due to infinite loop)
    close(server_fd);
    return 0;
}