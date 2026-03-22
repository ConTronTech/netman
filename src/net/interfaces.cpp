#include "interfaces.hpp"
#include "../helpers/exec.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <algorithm>

namespace fs = std::filesystem;

namespace interfaces {

// Parse /proc/net/dev for RX/TX bytes
static void get_traffic_stats(const std::string& name, uint64_t& rx, uint64_t& tx) {
    rx = 0;
    tx = 0;
    
    std::ifstream file("/proc/net/dev");
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.find(name + ":") != std::string::npos) {
            std::istringstream iss(line);
            std::string iface;
            iss >> iface >> rx;
            // Skip rx fields, get tx
            uint64_t dummy;
            for (int i = 0; i < 7; i++) iss >> dummy;
            iss >> tx;
            break;
        }
    }
}

// Parse iwconfig for signal strength
static int get_wifi_signal(const std::string& name) {
    std::string output = exec::run("iwconfig " + name + " 2>/dev/null");
    
    // Look for "Signal level=-XX dBm" or "Link Quality=XX/70"
    std::regex signal_regex("Signal level[=:]\\s*(-?\\d+)");
    std::regex quality_regex("Link Quality[=:]\\s*(\\d+)/(\\d+)");
    std::smatch match;
    
    if (std::regex_search(output, match, quality_regex)) {
        int current = std::stoi(match[1]);
        int max = std::stoi(match[2]);
        return (current * 100) / max;
    }
    
    if (std::regex_search(output, match, signal_regex)) {
        int dbm = std::stoi(match[1]);
        // Convert dBm to percentage (rough approximation)
        // -30 dBm = 100%, -90 dBm = 0%
        int pct = (dbm + 90) * 100 / 60;
        return std::clamp(pct, 0, 100);
    }
    
    return -1; // Not a wifi interface
}

// Parse ip addr show for interface details
static Interface parse_interface(const std::string& name) {
    Interface iface;
    iface.name = name;
    iface.signal = -1;
    iface.rx_bytes = 0;
    iface.tx_bytes = 0;
    
    // Get state from /sys
    std::ifstream state_file("/sys/class/net/" + name + "/operstate");
    if (state_file) {
        std::getline(state_file, iface.state);
        // Capitalize
        std::transform(iface.state.begin(), iface.state.end(), 
                       iface.state.begin(), ::toupper);
    }
    
    // Get MAC from /sys
    std::ifstream mac_file("/sys/class/net/" + name + "/address");
    if (mac_file) {
        std::getline(mac_file, iface.mac);
        // Uppercase MAC
        std::transform(iface.mac.begin(), iface.mac.end(),
                       iface.mac.begin(), ::toupper);
    }
    
    // Get IP from ip addr
    std::string output = exec::run("ip -4 addr show " + name + " 2>/dev/null");
    std::regex ip_regex("inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
    std::smatch match;
    if (std::regex_search(output, match, ip_regex)) {
        iface.ip = match[1];
    }
    
    // Get traffic stats
    get_traffic_stats(name, iface.rx_bytes, iface.tx_bytes);
    
    // Get wifi signal if applicable
    if (name.find("wl") == 0 || name.find("wifi") == 0) {
        iface.signal = get_wifi_signal(name);
    }
    
    return iface;
}

std::vector<Interface> list() {
    std::vector<Interface> result;
    
    try {
        for (const auto& entry : fs::directory_iterator("/sys/class/net")) {
            std::string name = entry.path().filename().string();
            
            // Skip loopback
            if (name == "lo") continue;
            
            result.push_back(parse_interface(name));
        }
    } catch (...) {
        // Fallback: parse ip link
        std::string output = exec::run("ip link show");
        std::regex iface_regex("^\\d+:\\s+(\\w+):");
        std::smatch match;
        std::istringstream iss(output);
        std::string line;
        
        while (std::getline(iss, line)) {
            if (std::regex_search(line, match, iface_regex)) {
                std::string name = match[1];
                if (name != "lo") {
                    result.push_back(parse_interface(name));
                }
            }
        }
    }
    
    return result;
}

Interface get(const std::string& name) {
    return parse_interface(name);
}

bool set_state(const std::string& name, bool up) {
    std::string cmd = "ip link set " + name + (up ? " up" : " down");
    auto result = exec::run_root(cmd);
    return result.code == 0;
}

std::string get_dns() {
    std::ifstream file("/etc/resolv.conf");
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.find("nameserver") == 0) {
            std::istringstream iss(line);
            std::string ns, ip;
            iss >> ns >> ip;
            return ip;
        }
    }
    
    return "";
}

std::string get_default_gateway() {
    std::string output = exec::run("ip route show default 2>/dev/null");
    std::regex gw_regex("default via (\\d+\\.\\d+\\.\\d+\\.\\d+)");
    std::smatch match;
    
    if (std::regex_search(output, match, gw_regex)) {
        return match[1];
    }
    
    return "";
}

} // namespace interfaces
