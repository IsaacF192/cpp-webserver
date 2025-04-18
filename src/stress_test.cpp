#include <iostream>             // For console output
#include <thread>               // For std::thread
#include <vector>               // For std::vector
#include <curl/curl.h>          // For libcurl HTTP requests
#include <sstream>              // For building message text

// Function that sends a POST request to the server with a custom message
void send_request(int thread_id) {
    CURL* curl = curl_easy_init();  // Initialize CURL

    if (curl) {
        std::stringstream message;
        message << "message=Message+from+thread+" << thread_id;

        std::string post_data = message.str();  // Save POST data as string

        // Set headers to mimic a real HTML form submission
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8080/submit");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Thread " << thread_id << " failed: "
                      << curl_easy_strerror(res) << std::endl;
        } else {
            std::cout << "Thread " << thread_id << " sent message." << std::endl;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);  // Free headers
    }
}


int main() {
    const int NUM_THREADS = 50;                     // Number of requests to send
    std::vector<std::thread> threads;               // Container to hold thread objects

    curl_global_init(CURL_GLOBAL_ALL);              // Initialize CURL globally

    // Create and launch threads
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back(send_request, i);      // Launch thread and pass thread ID
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();                                   // Join each thread
    }

    curl_global_cleanup();                          // Clean up CURL global resources
    std::cout << "All threads completed." << std::endl;

    return 0;
}
