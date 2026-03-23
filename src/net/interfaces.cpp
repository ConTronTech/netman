#include "interfaces.hpp"
#include "../core/security_manager.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <algorithm>

namespace fs = std::filesystem;

namespace interfaces {

// Parse /proc/net/dev for RX/TX bytes (no shell, safe)
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
    // Name already validated by caller
    auto result = SEC.exec_timeout("iwconfig " + name + "", 5, false);
    std::string output = result.out;
    
    // Look for "Signal level=-XX dBm" or "Link Quality=XX/70"
    std::regex signal_regex("Signal level[=:]\\s*(-?\\d+)");
    std::regex quality_regex("Link Quality[=:]\\s*(\\d+)/(\\d+)");
    std::smatch match;
    
    if (std::regex_search(output, match, quality_regex)) {
        try {
            int current = std::stoi(match[1]);
            int max = std::stoi(match[2]);
            if (max > 0) return (current * 100) / max;
        } catch (...) {}
    }
    
    if (std::regex_search(output, match, signal_regex)) {
        try {
            int dbm = std::stoi(match[1]);
            // Convert dBm to percentage (rough approximation)
            // -30 dBm = 100%, -90 dBm = 0%
            int pct = (dbm + 90) * 100 / 60;
            return std::clamp(pct, 0, 100);
        } catch (...) {}
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
    
    // Validate interface name
    std::string safe_name = SEC.safe_interface(name);
    if (safe_name.empty()) {
        return iface;
    }
    
    // Get state from /sys (file read, no shell)
    std::string state_path = "/sys/class/net/" + safe_name + "/operstate";
    if (fs::exists(state_path)) {
        std::ifstream state_file(state_path);
        if (state_file) {
            std::getline(state_file, iface.state);
            // Capitalize
            std::transform(iface.state.begin(), iface.state.end(), 
                           iface.state.begin(), ::toupper);
        }
    }
    
    // Get MAC from /sys (file read, no shell)
    std::string mac_path = "/sys/class/net/" + safe_name + "/address";
    if (fs::exists(mac_path)) {
        std::ifstream mac_file(mac_path);
        if (mac_file) {
            std::string raw_mac;
            std::getline(mac_file, raw_mac);
            // Validate MAC before storing
            std::string safe_mac = SEC.safe_mac(raw_mac);
            if (!safe_mac.empty()) {
                iface.mac = safe_mac;
            }
        }
    }
    
    // Get IP from ip addr (shell command with validated input)
    auto ip_result = SEC.exec_timeout("ip -4 addr show " + safe_name, 5, false);
    std::regex ip_regex("inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
    std::smatch match;
    if (std::regex_search(ip_result.out, match, ip_regex)) {
        std::string ip_candidate = match[1];
        // Validate IP before storing
        std::string safe_ip = SEC.safe_ip(ip_candidate);
        if (!safe_ip.empty()) {
            iface.ip = safe_ip;
        }
    }
    
    // Get traffic stats (file read, no shell)
    get_traffic_stats(safe_name, iface.rx_bytes, iface.tx_bytes);
    
    // Get wifi signal if applicable
    if (safe_name.find("wl") == 0 || safe_name.find("wifi") == 0) {
        iface.signal = get_wifi_signal(safe_name);
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
            
            // Validate interface name before processing
            std::string safe_name = SEC.safe_interface(name);
            if (!safe_name.empty()) {
                result.push_back(parse_interface(safe_name));
            }
        }
    } catch (...) {
        // Fallback: parse ip link (no user input, safe)
        auto link_result = SEC.exec("ip link show", false);
        std::regex iface_regex("^\\d+:\\s+(\\w+):");
        std::smatch match;
        std::istringstream iss(link_result.out);
        std::string line;
        
        while (std::getline(iss, line)) {
            if (std::regex_search(line, match, iface_regex)) {
                std::string name = match[1];
                if (name != "lo") {
                    std::string safe_name = SEC.safe_interface(name);
                    if (!safe_name.empty()) {
                        result.push_back(parse_interface(safe_name));
                    }
                }
            }
        }
    }
    
    return result;
}

Interface get(const std::string& name) {
    std::string safe_name = SEC.safe_interface(name);
    if (safe_name.empty()) {
        return Interface{};
    }
    return parse_interface(safe_name);
}

bool set_state(const std::string& name, bool up) {
    std::string safe_name = SEC.safe_interface(name);
    if (safe_name.empty()) {
        SEC.log_attempt("set_state", "invalid interface: " + name, false);
        return false;
    }
    
    std::string cmd = "ip link set " + safe_name + (up ? " up" : " down");
    auto result = SEC.exec(cmd, true);
    return result.code == 0;
}

std::string get_dns() {
    // File read, no shell, no user input
    std::ifstream file("/etc/resolv.conf");
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.find("nameserver") == 0) {
            std::istringstream iss(line);
            std::string ns, ip;
            iss >> ns >> ip;
            // Validate IP before returning
            std::string safe_ip = SEC.safe_ip(ip);
            if (!safe_ip.empty()) {
                return safe_ip;
            }
        }
    }
    
    return "";
}

std::string get_default_gateway() {
    // No user input, safe command
    auto result = SEC.exec("ip route show default", false);
    std::regex gw_regex("default via (\\d+\\.\\d+\\.\\d+\\.\\d+)");
    std::smatch match;
    
    if (std::regex_search(result.out, match, gw_regex)) {
        std::string gw_candidate = match[1];
        // Validate IP before returning
        std::string safe_ip = SEC.safe_ip(gw_candidate);
        if (!safe_ip.empty()) {
            return safe_ip;
        }
    }
    
    return "";
}

} // namespace interfaces
