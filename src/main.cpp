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
       
       
        HttpResponse res(404, "<h1>404 Not Found</h1>");
        return res.to_string();

    }

    // File found — read it into a buffer
    std::stringstream buffer;
    buffer << file.rdbuf();            // Read entire file contents into buffer
    std::string body = buffer.str();   // Convert buffer to string

    // Build full HTTP response string
   HttpResponse res(200, body);
    return res.to_string();      // Return the full response string
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


std::string decode_form_value(const std::string& body) {
    std::string key = "message=";
    size_t pos = body.find(key);
    if (pos == std::string::npos) return "[empty]";

    std::string value = body.substr(pos + key.length());

    // Replace '+' with space (basic decoding)
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '+') value[i] = ' ';
    }

    return value;
}



class HttpRequest {
public:
    std::string method;
    std::string path;
    std::string body;

    // Constructor that takes in the raw request string
    HttpRequest(const std::string& raw_request) {
        parse(raw_request);
    }

private:
    void parse(const std::string& request) {
        std::istringstream stream(request);

        // Parse first line: e.g. "GET /index.html HTTP/1.1"
        stream >> method >> path;

        // Find start of body (after blank line)
        size_t pos = request.find("\r\n\r\n");
        if (pos != std::string::npos) {
            body = request.substr(pos + 4);  // Body starts after \r\n\r\n
        }
    }
};


// Class to represent and build an HTTP response

class HttpResponse {
public:
    int status_code;
    std::string status_text;
    std::string content_type = "text/html"; // Default content type
    std::string body;

    // Constructor: takes status code and optional body
    HttpResponse(int code, const std::string& body_content)
        : status_code(code), body(body_content) {
        set_status_text();  // Set default status text like "OK" or "Not Found"
    }

    // Build the full HTTP response string
    
    std::string to_string() const {
        std::stringstream response;

        // Status line
        response << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";

        // Headers
        response << "Content-Type: " << content_type << "\r\n";
        response << "Content-Length: " << body.size() << "\r\n";
        response << "\r\n";

        // Body
        response << body;

        return response.str();
    }
    
    private:
    void set_status_text() {
        // Set default status text based on code
        if (status_code == 200) status_text = "OK";
        else if (status_code == 404) status_text = "Not Found";
        else if (status_code == 400) status_text = "Bad Request";
        else status_text = "Unknown";
    }
};












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
        
        HttpRequest req(request);  // Create HttpRequest instance and parse
        std::string method = req.method;
        std::string path = req.path;
        std::string body = req.body;



std::string response;

if (method == "GET") {
    response = get_http_response(path);
    
    } else if (method == "POST" && path == "/submit") {
    std::string clean_message = decode_form_value(body);

    std::ofstream file("submissions.txt", std::ios::app);
    if (file) {
        file << clean_message << "\n---\n";
    }

    
    HttpResponse res(200, "<h1>Thanks for your submission!</h1>");
    
    response = res.to_string();


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