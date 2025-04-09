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
    if (!logfile.is_open()) return;

    // Get current time
    std::time_t now = std::time(nullptr);
    char* timestamp = std::ctime(&now); // e.g. "Mon Apr 8 22:35:00 2025\n"
    timestamp[strlen(timestamp) - 1] = '\0'; // remove newline character

    // Format: [LEVEL] [TIMESTAMP] message
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
