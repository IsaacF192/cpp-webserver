// utils.h

#ifndef UTILS_H
#define UTILS_H

#include <string>  // For std::string

// Function to sanitize a string for safe HTML rendering
// Replaces characters like <, >, &, ", and ' with HTML-safe equivalents
std::string sanitize(const std::string& input);

#endif
