#include <iostream>       // for std::cout, std::cerr
#include <fstream>        // for file reading (serving HTML files)
#include <sstream>        // for string streams (building HTTP responses)
#include <string>         // for std::string
#include <cstring>        // for memset and C-string functions
#include <unistd.h>       // for close(), read(), write()
#include <netinet/in.h>   // for sockaddr_in, socket functions
#include <sys/socket.h>   // for socket(), bind(), listen(), accept()
#include "logger.h"

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
std::string parse_request_path(const std::string& request, std::string& method, std::string& body) 
{
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


// Helper function to decode URL-encoded strings (e.g. %2E%2E → ..)
std::string url_decode(const std::string& input) {
    std::string result;  // Stores the decoded output
    char ch;             // Holds the decoded character
    int i, ii;           // 'i' is the loop index, 'ii' holds the hex value

    // Loop through each character in the input string
    for (i = 0; i < input.length(); i++) {
        // If the current character is '%' (URL encoding indicator)
        if (int(input[i]) == 37) { // 37 is ASCII for '%'
            // Get the two characters following '%', convert from hex to int
            sscanf(input.substr(i + 1, 2).c_str(), "%x", &ii);

            // Cast the int to a char and add it to the result
            ch = static_cast<char>(ii);
            result += ch;

            // Skip the two characters we just processed
            i = i + 2;
        } else {
            // If it's not a '%', just add the character as-is
            result += input[i];
        }
    }

    // Return the fully decoded string
    return result;
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





// HttpServer class: handles listening, accepting connections, and serving responses
class HttpServer {
public:
    HttpServer(int port) : port(port) {
        setup_socket();
    }

    ~HttpServer() {
        // RAII: automatically close server socket on destruction
        if (server_fd >= 0) {
            close(server_fd);
            std::cout << "Server socket closed." << std::endl;
        }
    }

    // Main server loop: accepts requests and returns responses
    void run() {
        Logger logger("server.log"); // Log to server.log
        std::cout << "Server listening on port " << port << "..." << std::endl;
        logger.log(Logger::INFO, "Server started on port " + std::to_string(port));

        while (true) {
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd < 0) {
                logger.log(Logger::ERROR, "accept() failed");
                continue;
            }

            char buffer[4096] = {0};
            read(client_fd, buffer, sizeof(buffer));

            HttpRequest req(buffer);  // Parse the raw HTTP request

            // Decode any URL-encoded characters in the path (e.g. %2E%2E → ..)
            // This prevents encoded directory traversal attacks from slipping past validation
            // For example, a browser might encode "../../etc/passwd" as "%2E%2E/%2E%2E/etc/passwd"
            // Without decoding, our ".." check would miss it — so we decode first
            req.path = url_decode(req.path);





            logger.log(Logger::INFO, "Received " + req.method + " request for " + req.path);

            std::string response;

            if (req.method == "GET") {

                // 🔐 Check for directory traversal attempt in the requested path
                
                if (req.path.find("..") != std::string::npos) {
                    
                    // 🚨 Log an error if the path contains "..", which is a potential security risk
                    logger.log(Logger::ERROR, "Blocked path traversal attempt: " + req.path);

                     // 🛑 Create a 403 Forbidden response because the request is unsafe
                    HttpResponse res(403, "<h1>403 Forbidden</h1>");

                     // 📦 Convert the HttpResponse to a full HTTP-formatted string
                    response = res.to_string();

                     // 📤 Send the response back to the client
                    send(client_fd, response.c_str(), response.size(), 0);

                     // 🔒 Close the connection to the client to end the request
                    close(client_fd);


                     // 🔁 Skip the rest of the loop and wait for the next client connection
                     continue;
                     
                     }




                // Try to open the requested file
                std::string full_path = ROOT_DIR + (req.path == "/" ? "/index.html" : req.path);
                std::ifstream file(full_path);

                if (!file) {
                    logger.log(Logger::ERROR, "File not found: " + req.path);
                    HttpResponse res(404, "<h1>404 Not Found</h1>");
                    response = res.to_string();
                } else {
                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    HttpResponse res(200, buffer.str());
                    response = res.to_string();
                }
            }
            else if (req.method == "POST" && req.path == "/submit") {
                std::string clean_message = decode_form_value(req.body);

                std::ofstream file("submissions.txt", std::ios::app);
                if (file) {
                    file << clean_message << "\n---\n";
                }

                logger.log(Logger::INFO, "Form submitted with message: " + clean_message);

                HttpResponse res(200, "<h1>Thanks for your submission!</h1>");
                response = res.to_string();
            }
            else {
                logger.log(Logger::WARNING, "Unsupported request: " + req.method + " " + req.path);
                HttpResponse res(400, "<h1>400 Bad Request</h1>");
                response = res.to_string();
            }

            send(client_fd, response.c_str(), response.size(), 0);
            close(client_fd); // Close connection to the client
        }
    }

private:
    int server_fd = -1;
    int port;

    void setup_socket() {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }

        if (listen(server_fd, 10) < 0) {
            perror("listen failed");
            exit(EXIT_FAILURE);
        }
    }
};















int main() {

    HttpServer server(8080);  // Create server on port 8080
    server.run();             // Start accepting requests
    return 0;








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