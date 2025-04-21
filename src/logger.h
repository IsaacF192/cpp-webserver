#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>  

// Logger class for writing messages to a log file
class Logger {
public:
    // Levels of logging
    enum Level {
        INFO,
        WARNING,
        ERROR
    };

    // Constructor: opens the log file for appending
    Logger(const std::string& filename);

    // Destructor: closes the file if open (RAII)
    ~Logger();

    // Write a log message with a given severity level
    void log(Level level, const std::string& message);
    // Helper method to convert Level enum to a string
    std::string levelToString(Level level);

private:
    std::ofstream logfile;  // Output stream for log file
    
    std::mutex log_mutex;  // Protects logfile access from concurrent threads to ensure thread-safe logging
};

#endif
