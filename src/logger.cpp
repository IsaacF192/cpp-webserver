#include "logger.h"
#include <ctime>     // for time()
#include <iostream>  // optional: for debug output
#include <cstring>   // for strlen()

// Constructor: open the log file in append mode
Logger::Logger(const std::string& filename) {
    logfile.open(filename, std::ios::app);  // append mode
}

// Destructor: close the log file if it's open
Logger::~Logger() {
    if (logfile.is_open()) {
        logfile.close();
    }
}

// Write a log entry with a timestamp and log level
void Logger::log(Level level, const std::string& message) {

    // Acquire a lock on the mutex to ensure only one thread can write to the log file at a time
    std::lock_guard<std::mutex> lock(log_mutex);  

    // Check if the log file is open; if not, exit the function
    if (!logfile.is_open()) return;

    // Get the current system time as a time_t object
    std::time_t now = std::time(nullptr);

    // Convert the time_t object to a human-readable string (e.g. "Thu Apr 25 14:05:32 2024")
    char* timestamp = std::ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // remove newline character

    // Write the log entry to the file in the format: [LEVEL] [TIMESTAMP] message
    logfile << "[" << levelToString(level) << "] "
            << "[" << timestamp << "] "
            << message << std::endl;
}

// Convert enum to readable string
std::string Logger::levelToString(Level level) {
    switch (level) {
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}
