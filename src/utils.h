#ifndef UTILS_H
#define UTILS_H

#include <string>  // For std::string

// Function to sanitise a string for safe HTML rendering
// Replaces characters like <, >, &, ", and ' with HTML safe equivalents
std::string sanitise(const std::string& input);

#endif
