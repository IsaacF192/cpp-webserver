// utils.cpp
#include "utils.h"    // Include the header for function declaration

// Function to sanitise a string for HTML output
// This helps prevent cross-site scripting (XSS) by escaping HTML characters
std::string sanitise(const std::string& input) {
    std::string safe;  // This will store the sanitized result

    // Loop through each character in the input string
    for (char c : input) {
        switch (c) {
            case '<':
                // Replace less-than with HTML entity
                safe += "&lt;";
                break;
            case '>':
                // Replace greater-than with HTML entity
                safe += "&gt;";
                break;
            case '&':
                // Replace ampersand with HTML entity
                safe += "&amp;";
                break;
            case '"':
                // Replace double-quote with HTML entity
                safe += "&quot;";
                break;
            case '\'':
                // Replace single-quote with HTML entity
                safe += "&#39;";
                break;
            default:
                // Keep character as it is if its safe
                safe += c;
        }
    }

    // Return the fully sanitised string
    return safe;
}
