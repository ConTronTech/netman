#pragma once

#include <string>

namespace exec {

struct Result {
    int code;
    std::string out;
    std::string err;
};

// Run command, return stdout only
std::string run(const std::string& cmd);

// Run command, return exit code + stdout + stderr
Result run_full(const std::string& cmd);

// Run as root via pkexec
Result run_root(const std::string& cmd);

} // namespace exec
