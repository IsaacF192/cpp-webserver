#include <iostream>       // for std::cout, std::cerr
#include <fstream>        // for file reading (serving HTML files)
#include <sstream>        // for string streams (building HTTP responses)
#include <string>         // for std::string
#include <cstring>        // for memset and C-string functions
#include <unistd.h>       // for close(), read(), write()
#include <netinet/in.h>   // for sockaddr_in, socket functions
#include <sys/socket.h>   // for socket(), bind(), listen(), accept()
#include "logger.h"
#include <thread> // for std::thread
#include "utils.h"
#include <mutex> // for std::mutex
#include "threadpool.h"
#include <chrono>  // to simulate a slow response or delay, to test how the server works concurrency, also used for precise timestamps
#include <unordered_map> // to track client request times
#include <sys/time.h> // gives acces to struct timeval which is a data structure used in many system calls to represent a time duration
#include <limits.h>
#include <unistd.h>
std::mutex file_mutex; //this is a global mutex to protect file writes accross threads.


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


// Extracts the value of the "message" parameter from the POST body
std::string decode_form_value(const std::string& body) {
    std::string key = "message=";                    //define the key we're looking for
    size_t pos = body.find(key);                     //search for message= in the post body
    if (pos == std::string::npos) return "[empty]";  // if not found, return an empty string

    std::string value = body.substr(pos + key.length());   //extract the value after message
    

    //loop through each character in the value 
    // Replace '+' with space, '+' represents spaces in URL-encoded form data
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '+') value[i] = ' ';
    }

    return value; //return clean value
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
    
    static void handle_client(int client_fd);
    
    
    std::unordered_map<int, std::chrono::steady_clock::time_point> last_request_time;
    std::mutex throttle_mutex;  // Protect access to the map

    
    
    
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

        ThreadPool pool(8, this);
        
        while (true){
            
            int client_fd = accept(server_fd, nullptr, nullptr);   //Accept a new client connection (blocks until a client connects)
            
            if (client_fd < 0) {

                logger.log(Logger::ERROR, "accept() failed");  // Log failure to accept
                continue;  // Try again
                }
                
                struct timeval timeout;
                timeout.tv_sec = 10;
                timeout.tv_usec = 0;
                setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
                 
                
     {
                
                std::lock_guard<std::mutex> lock(throttle_mutex);
                
                auto now = std::chrono::steady_clock::now();
                auto it = last_request_time.find(client_fd);
                
                if (it != last_request_time.end()) {
                    
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count();
                    
                    if (elapsed < 1000) { //Limit to 1 request per second
                    
                    logger.log(Logger::WARNING, "Request throttled (too frequent)");
                    close(client_fd);
                    continue;
        }
    }

    last_request_time[client_fd] = now;  // Update last request time
    
    }
    
    pool.enqueue(client_fd);

    std::cout << "[Debug] Enqueued client_fd " << client_fd << std::endl;


    //Start a new thread to handle the client
    //std::thread client_thread(&HttpServer::handle_client, this, client_fd);

    //Detach the thread so it runs independently and cleans up on its own
    //client_thread.detach();
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

// This method handles a single client connection.
// It's exactly the logic that used to live in the `run()` method.
// It gets called from a new thread for each client.

void handle_client(int client_fd) {
    
    Logger logger("server.log");  // Create a logger for this request/thread

    std::cout << "[Debug] handle_client() started\n";

   
    
    // Create a string to store the full incoming requess
    std::string request_data;
    char buffer[1024];  // Use a smaller buffer to read in chunks
    ssize_t bytes_read;
    bool complete = false;
    
    auto start_time = std::chrono::steady_clock::now();  // Track how long the request is taking
    
    
    while (!complete) {
        
        // Read part of the request
        bytes_read = read(client_fd, buffer, sizeof(buffer));
        std::cout << "[Debug] Bytes read: " << bytes_read << std::endl;

    if (bytes_read <= 0) {
        
        // If read failed or timed out, close the connection
        logger.log(Logger::WARNING, "Client read timed out or failed");

        int err = errno;
        std::cerr << "[Debug] read() error code: " << err 
          << " (" << strerror(err) << ")" << std::endl;

        //std::cerr << "[Debug] read() error: " << strerror(errno) << std::endl;

        //std::cout << "[Debug] Read timed out or failed\n";
        close(client_fd);

        return;
    }
    
    // Append the new bytes to the full request string
    request_data.append(buffer, bytes_read);

    //Debug: Print what has been received so far
    std::cout << "Partial request so far:\n" << request_data << std::endl;

    // Check if we've reached the end of HTTP headers (\r\n\r\n)
    if (request_data.find("\r\n\r\n") != std::string::npos) {
        std::cout << "[Debug] End of headers found\n";
        complete = true;  // Stop reading once headers are complete
    }

    // extra protection layer
    auto now = std::chrono::steady_clock::now();             // Total time spent reading the request so far
    if (std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count() > 10) {
        logger.log(Logger::WARNING, "Client took too long to complete request");

        std::cout << "[Debug] Client took too long\n";

        // Fail-safe: client is sending too slowly
        close(client_fd);
        return;
    }
}

if (request_data.empty()) {
    logger.log(Logger::WARNING, "Empty or incomplete request");

    std::cout << "[Debug] Request was empty\n";

    HttpResponse res(400, "<h1>400 Bad Request</h1>");
    std::string response = res.to_string();
    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
    return;
}

std::cout << "[Debug] Creating HttpRequest object\n";

// Now that we have a full request, parse it
HttpRequest req(request_data);  // Safely construct the request



    //req.path = url_decode(req.path);   // Decode %2E%2E and other encoded path parts
    //std::string response;  // This will hold the final HTTP response

    
    std::string response;  // This will hold the final HTTP response


   // Decode the path first
std::string decoded_path = url_decode(req.path);
std::string full_path = ROOT_DIR + (decoded_path == "/" ? "/index.html" : decoded_path);

char resolved_path[PATH_MAX];
char root_path[PATH_MAX];
realpath(ROOT_DIR.c_str(), root_path);

// Try to resolve the requested file path
if (!realpath(full_path.c_str(), resolved_path)) {
    // If resolution fails AND the decoded path has traversal
    if (decoded_path.find("..") != std::string::npos) {
        logger.log(Logger::ERROR, "Blocked traversal (unresolved): " + decoded_path);
        HttpResponse res(403, "<h1>403 Forbidden</h1>");
        response = res.to_string();
    } else {
        logger.log(Logger::ERROR, "File not found or unresolved: " + full_path);
        HttpResponse res(404, "<h1>404 Not Found</h1>");
        response = res.to_string();
    }
    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
    return;
}

//Confirm resolved path is still inside ROOT_DIR
if (strncmp(resolved_path, root_path, strlen(root_path)) != 0) {
    logger.log(Logger::ERROR, "Blocked traversal: " + decoded_path);
    HttpResponse res(403, "<h1>403 Forbidden</h1>");
    response = res.to_string();
    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
    return;
}

// Safe path update request
req.path = decoded_path;
        
        
        logger.log(Logger::INFO, "Received " + req.method + " request for " + req.path);

    
    
    //Handle GET requests
    if (req.method == "GET") {

        if (req.path == "/messages.html") {
            std::ifstream file("submissions.txt");       // Try to read the saved submissions
            std::stringstream content;                   // Buffer for building HTML page

            // Start HTML document
            content << "<!DOCTYPE html><html><head><title>Messages</title>";
            content << "<style>";
            content << "body { font-family: sans-serif; padding: 20px; background: #f0f0f0; }";
            content << ".msg { background: white; border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; white-space: pre-wrap; }";
            content << "</style>";
            content << "</head><body>";
            content << "<h1>Submitted Messages</h1>";

            // Loop through file and wrap each message in a div
            std::string line;
            std::string message;
            
            while (std::getline(file, line)) {
                
                if (line == "---") {
                    //std::string decoded_message = url_decode(message); 
                    std::string safe_message = sanitise(message); // sanitise message before output
                    
                    // End of a message wrap and reset
                    content << "<div class='msg'>" << safe_message << "</div>";
                    message.clear();
                    } else {
                        message += line + "\n";  // Add line to current message
                        }
            }

            // Catch any trailing message without ---
            if (!message.empty()) {
                std::string safe_message = sanitise(message); // sanitise message before output
                content << "<div class='msg'>" << safe_message << "</div>";}




            content << "</body></html>";
            
            HttpResponse res(200, content.str());        // Wrap the content in a valid HTTP response
            response = res.to_string();
            
            send(client_fd, response.c_str(), response.size(), 0); // Send to browser
            close(client_fd);
            
            return; // Exit early (skip file serving)
}


// Security: prevent directory traversal (e.g., "../etc/passwd")

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

        //std::this_thread::sleep_for(std::chrono::seconds(5));  // Simulates slow responses or delay
    }
    
     // Handle POST request for form submission
    else if (req.method == "POST" && req.path == "/submit") {
        std::string raw_message = decode_form_value(req.body);  // Extract and clean form data
        std::string decoded_message = url_decode(raw_message);           // Decode URL-encoded characters
       
       
       { // Start a block scope to limit how long the lock is held
        
        
        std::lock_guard<std::mutex> lock(file_mutex); // Lock the mutex to ensure this block is thread-safe.
                                                      //only one thread can the hole the lock at a time
                                                      
        // Open file in append mode which mean new messages are added to the end
        std::ofstream file("submissions.txt", std::ios::app);     
        if (file) {

            file << decoded_message << "\n---\n";  // Store the message, 
            // Write the decoded message followed by separator to the file.

        }
        
        
        } // The lock is automatically released here when 'lock' goes out of scope

        logger.log(Logger::INFO, "Form submitted with message: " + decoded_message);
        logger.log(Logger::INFO, "Form submitted with message: " + raw_message);
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



int main() {

    HttpServer server(8080);  // Create server on port 8080
    server.run();             // Start accepting requests
    return 0;

}