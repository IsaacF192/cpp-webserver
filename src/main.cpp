#include <iostream>       // for std::cout, std::cerr
#include <fstream>        // for file reading (serving HTML files)
#include <sstream>        // for string streams (building HTTP responses)
#include <string>         // for std::string
#include <cstring>        // for memset and C-string functions
#include <unistd.h>       // for close(), read(), write()
#include <netinet/in.h>   // for sockaddr_in, socket functions
#include <sys/socket.h>   // for socket(), bind(), listen(), accept()
#include <logger.h>
#include <thread> // for std::thread

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
        // File doesn't exist return 404 response
        std::string not_found =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<h1>404 Not Found</h1>";
        return not_found;
    }

    // File found read it into a buffer
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


// Helper function to decode URL-encoded strings (e.g. %2E%2E ..)
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

        while (true){
    //Accept a new client connection (blocks until a client connects)
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        logger.log(Logger::ERROR, "accept() failed");  // Log failure to accept
        continue;  // Try again
    }

    //Start a new thread to handle the client
    std::thread client_thread(&HttpServer::handle_client, this, client_fd);

    //Detach the thread so it runs independently and cleans up on its own
    client_thread.detach();
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
    
    
    // This method handles a single client connection.
    // It's exactly the logic that used to live in the `run()` method.
    // It gets called from a new thread for each client.
    
    
    void handle_client(int client_fd) {
    Logger logger("server.log");  // Create a logger for this request/thread

    char buffer[4096] = {0};  // Create a buffer to store the client's request
    read(client_fd, buffer, sizeof(buffer));  // Read the raw request from the socket

    HttpRequest req(buffer);           // Parse method, path, body
    req.path = url_decode(req.path);   // Decode %2E%2E and other encoded path parts

    logger.log(Logger::INFO, "Received " + req.method + " request for " + req.path);

    std::string response;  // This will hold the final HTTP response

    //Handle GET requests
    if (req.method == "GET") {
        // Security: prevent directory traversal (e.g., "../etc/passwd")
        if (req.path.find("..") != std::string::npos) {
            logger.log(Logger::ERROR, "Blocked path traversal attempt: " + req.path);
            HttpResponse res(403, "<h1>403 Forbidden</h1>");
            response = res.to_string();
            send(client_fd, response.c_str(), response.size(), 0);
            close(client_fd);
            return;  // Stop processing this request
        }

        // Build full path to the requested file
        std::string full_path = ROOT_DIR + (req.path == "/" ? "/index.html" : req.path);
        std::ifstream file(full_path);  // Try to open the file

        if (!file) {
            //File not found return 404
            logger.log(Logger::ERROR, "File not found: " + req.path);
            HttpResponse res(404, "<h1>404 Not Found</h1>");
            response = res.to_string();
        } else {
            //File found load contents into response
            std::stringstream buffer;
            buffer << file.rdbuf();  // Read entire file into buffer
            HttpResponse res(200, buffer.str());  // Create 200 OK response
            response = res.to_string();
        }
    }

    // Handle POST request for form submission
    else if (req.method == "POST" && req.path == "/submit") {
        std::string clean_message = decode_form_value(req.body);  // Extract and clean form data
        std::ofstream file("submissions.txt", std::ios::app);     // Open file in append mode
        if (file) {
            file << clean_message << "\n---\n";  // Store the message
        }

        logger.log(Logger::INFO, "Form submitted with message: " + clean_message);
        HttpResponse res(200, "<h1>Thanks for your submission!</h1>");
        response = res.to_string();
    }

    // Handle unsupported methods or invalid paths
    else {
        logger.log(Logger::WARNING, "Unsupported request: " + req.method + " " + req.path);
        HttpResponse res(400, "<h1>400 Bad Request</h1>");
        response = res.to_string();
    }

    // Send the response and close the connection
    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);  // Always close the client socket after responding
}

};








int main() {

    HttpServer server(8080);  // Create server on port 8080
    server.run();             // Start accepting requests
    return 0;

}