#include "mac_spoofer.hpp"
#include "../core/security_manager.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <mutex>
#include <filesystem>

namespace mac_spoofer {

// Static storage with thread safety
static std::map<std::string, std::string> s_original_macs;
static std::vector<SpoofEvent> s_history;
static std::atomic<bool> s_monitoring{false};
static std::thread s_monitor_thread;
static std::mutex s_state_mutex;

// Vendor prefixes (common ones)
static std::vector<VendorPrefix> s_vendors = {
    {"Apple", "00:1C:B3"},
    {"Apple", "3C:06:30"},
    {"Samsung", "00:1A:8A"},
    {"Samsung", "5C:3C:27"},
    {"Intel", "00:1E:67"},
    {"Intel", "3C:97:0E"},
    {"Google", "94:EB:2C"},
    {"Microsoft", "00:50:F2"},
    {"Cisco", "00:1B:D4"},
    {"Dell", "00:14:22"},
    {"HP", "00:1E:0B"},
    {"Lenovo", "00:1E:4F"},
    {"ASUS", "00:1A:92"},
    {"TP-Link", "00:1D:0F"},
    {"Netgear", "00:1E:2A"},
    {"Raspberry Pi", "B8:27:EB"},
    {"Random", ""},
};

std::vector<VendorPrefix> get_vendors() {
    return s_vendors;
}

std::string get_current_mac(const std::string& iface) {
    // Validate interface name to prevent path traversal
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return "";
    
    // Read from /sys (no shell execution)
    std::string path = "/sys/class/net/" + safe_iface + "/address";
    
    // Verify path is under /sys/class/net (defense in depth)
    if (!std::filesystem::exists(path)) return "";
    
    std::ifstream file(path);
    std::string mac;
    if (file) {
        std::getline(file, mac);
        // Validate the MAC we read
        auto result = SEC.validate(security::InputType::MAC_ADDRESS, mac);
        if (result.valid) {
            return result.sanitized;
        }
    }
    return "";
}

std::string get_original_mac(const std::string& iface) {
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return "";
    
    std::lock_guard<std::mutex> lock(s_state_mutex);
    auto it = s_original_macs.find(safe_iface);
    if (it != s_original_macs.end()) {
        return it->second;
    }
    // Not stored yet, current is original
    return get_current_mac(safe_iface);
}

void store_original_mac(const std::string& iface) {
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return;
    
    std::lock_guard<std::mutex> lock(s_state_mutex);
    if (s_original_macs.find(safe_iface) == s_original_macs.end()) {
        std::string mac = get_current_mac(safe_iface);
        if (!mac.empty()) {
            s_original_macs[safe_iface] = mac;
        }
    }
}

std::string generate_random_mac() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        int byte = dis(gen);
        // First byte: clear multicast bit, set local bit
        if (i == 0) {
            byte = (byte & 0xFE) | 0x02;
        }
        ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << byte;
        if (i < 5) ss << ":";
    }
    return ss.str();
}

std::string generate_vendor_mac(const std::string& vendor) {
    // Find vendor prefix
    std::string prefix;
    for (const auto& v : s_vendors) {
        if (v.name == vendor && !v.prefix.empty()) {
            prefix = v.prefix;
            break;
        }
    }
    
    if (prefix.empty()) {
        return generate_random_mac();
    }
    
    // Generate random suffix
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    ss << prefix;
    for (int i = 0; i < 3; i++) {
        ss << ":" << std::uppercase << std::hex << std::setfill('0') 
           << std::setw(2) << dis(gen);
    }
    return ss.str();
}

bool is_valid_mac(const std::string& mac) {
    auto result = SEC.validate(security::InputType::MAC_ADDRESS, mac);
    return result.valid;
}

bool apply_mac(const std::string& iface, const std::string& new_mac) {
    // Validate inputs
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) {
        SEC.log_attempt("apply_mac", "invalid interface: " + iface, false);
        return false;
    }
    
    std::string safe_mac = SEC.safe_mac(new_mac);
    if (safe_mac.empty()) {
        SEC.log_attempt("apply_mac", "invalid MAC: " + new_mac, false);
        return false;
    }
    
    // Store original first
    store_original_mac(safe_iface);
    
    std::string old_mac = get_current_mac(safe_iface);
    
    // Bring interface down
    auto r1 = SEC.exec("ip link set " + safe_iface + " down", true);
    if (r1.code != 0) {
        SEC.log_attempt("apply_mac", "failed to bring down " + safe_iface, false);
        return false;
    }
    
    // Set new MAC
    auto r2 = SEC.exec("ip link set " + safe_iface + " address " + safe_mac, true);
    if (r2.code != 0) {
        // Try to bring back up even if failed
        SEC.exec("ip link set " + safe_iface + " up", true);
        SEC.log_attempt("apply_mac", "failed to set MAC on " + safe_iface, false);
        return false;
    }
    
    // Bring interface up
    auto r3 = SEC.exec("ip link set " + safe_iface + " up", true);
    
    // Add to history
    SpoofEvent event;
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&time));
    event.timestamp = buf;
    event.interface = safe_iface;
    event.old_mac = old_mac;
    event.new_mac = safe_mac;
    event.ssid = get_ssid(safe_iface);
    add_history(event);
    
    SEC.log_attempt("apply_mac", safe_iface + " -> " + safe_mac, true);
    return r3.code == 0;
}

bool restore_original(const std::string& iface) {
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return false;
    
    std::string original = get_original_mac(safe_iface);
    if (original.empty()) return false;
    
    return apply_mac(safe_iface, original);
}

std::string get_ssid(const std::string& iface) {
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return "Not Connected";
    
    auto result = SEC.exec_timeout("iwgetid " + safe_iface + " -r", 3, false);
    std::string output = result.out;
    
    // Trim newline
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    
    if (output.empty()) return "Not Connected";
    
    // Sanitize SSID output (could contain anything)
    std::string sanitized;
    for (char c : output) {
        if (c >= 32 && c < 127) {
            sanitized += c;
        }
    }
    
    return sanitized.empty() ? "Not Connected" : sanitized;
}

bool is_wifi_connected(const std::string& iface) {
    std::string ssid = get_ssid(iface);
    return !ssid.empty() && ssid != "Not Connected";
}

bool has_internet() {
    // Quick connectivity check - no user input, safe command
    auto result = SEC.exec_timeout(
        "curl -s --connect-timeout 3 --max-time 5 http://captive.apple.com/hotspot-detect.html",
        10, false);
    return result.out.find("Success") != std::string::npos;
}

bool is_captive_portal() {
    auto result = SEC.exec_timeout(
        "curl -s --connect-timeout 3 --max-time 5 http://captive.apple.com/hotspot-detect.html",
        10, false);
    
    if (result.out.find("Success") != std::string::npos) {
        return false;  // Normal internet
    }
    if (result.out.find("<html") != std::string::npos ||
        result.out.find("paused") != std::string::npos ||
        result.out.find("xfinity") != std::string::npos ||
        result.out.find("captive") != std::string::npos) {
        return true;  // Captive portal detected
    }
    return false;
}

void start_monitor(const std::string& iface, int interval_sec,
                   bool lock_to_network, const std::string& target_ssid,
                   bool notifications, SpoofCallback callback) {
    // Validate interface upfront
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return;
    
    // Sanitize SSID if provided
    std::string safe_target_ssid;
    if (lock_to_network && !target_ssid.empty()) {
        auto ssid_result = SEC.validate(security::InputType::SSID, target_ssid);
        if (ssid_result.valid) {
            safe_target_ssid = ssid_result.sanitized;
        }
    }
    
    // Clamp interval
    if (interval_sec < 5) interval_sec = 5;
    if (interval_sec > 3600) interval_sec = 3600;
    
    if (s_monitoring) {
        stop_monitor();
    }
    
    s_monitoring = true;
    
    s_monitor_thread = std::thread([=]() {
        bool last_connected = is_wifi_connected(safe_iface);
        std::string last_ssid = get_ssid(safe_iface);
        
        while (s_monitoring) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
            
            if (!s_monitoring) break;
            
            bool connected = is_wifi_connected(safe_iface);
            std::string current_ssid = get_ssid(safe_iface);
            
            // Reconnection detected
            if (connected && !last_connected) {
                // Check if we should spoof
                bool should_spoof = true;
                if (lock_to_network && current_ssid != safe_target_ssid) {
                    should_spoof = false;
                }
                
                if (should_spoof) {
                    std::string new_mac = generate_random_mac();
                    if (apply_mac(safe_iface, new_mac) && callback) {
                        SpoofEvent event;
                        event.interface = safe_iface;
                        event.new_mac = new_mac;
                        event.ssid = current_ssid;
                        callback(event);
                    }
                }
            }
            
            last_connected = connected;
            last_ssid = current_ssid;
        }
    });
}

void stop_monitor() {
    s_monitoring = false;
    if (s_monitor_thread.joinable()) {
        s_monitor_thread.join();
    }
}

bool is_monitoring() {
    return s_monitoring;
}

std::vector<SpoofEvent> get_history() {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    return s_history;
}

void add_history(const SpoofEvent& event) {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_history.insert(s_history.begin(), event);
    // Keep only last 50
    if (s_history.size() > 50) {
        s_history.resize(50);
    }
}

void clear_history() {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_history.clear();
}

} // namespace mac_spoofer
