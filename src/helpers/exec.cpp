#include "exec.hpp"
#include <array>
#include <memory>
#include <cstdio>
#include <stdexcept>

namespace exec {

std::string run(const std::string& cmd) {
    std::array<char, 4096> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(
        popen(cmd.c_str(), "r"), pclose);
    
    if (!pipe) {
        return "";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

Result run_full(const std::string& cmd) {
    Result res;
    
    // Redirect stderr to stdout for capture
    std::string full_cmd = cmd + " 2>&1";
    
    std::array<char, 4096> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(
        popen(full_cmd.c_str(), "r"), pclose);
    
    if (!pipe) {
        res.code = -1;
        res.err = "Failed to execute command";
        return res;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        res.out += buffer.data();
    }
    
    // Get exit code
    int status = pclose(pipe.release());
    res.code = WEXITSTATUS(status);
    
    return res;
}

Result run_root(const std::string& cmd) {
    // App runs as root, so just run directly
    return run_full(cmd);
}

} // namespace exec
