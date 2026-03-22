#include "mac_spoofer.hpp"
#include "../helpers/exec.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <algorithm>

namespace mac_spoofer {

// Static storage
static std::map<std::string, std::string> original_macs;
static std::vector<SpoofEvent> history;
static std::atomic<bool> monitoring{false};
static std::thread monitor_thread;

// Vendor prefixes (common ones)
static std::vector<VendorPrefix> vendors = {
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
    return vendors;
}

std::string get_current_mac(const std::string& iface) {
    std::ifstream file("/sys/class/net/" + iface + "/address");
    std::string mac;
    if (file) {
        std::getline(file, mac);
        std::transform(mac.begin(), mac.end(), mac.begin(), ::toupper);
    }
    return mac;
}

std::string get_original_mac(const std::string& iface) {
    auto it = original_macs.find(iface);
    if (it != original_macs.end()) {
        return it->second;
    }
    // Not stored yet, current is original
    return get_current_mac(iface);
}

void store_original_mac(const std::string& iface) {
    if (original_macs.find(iface) == original_macs.end()) {
        original_macs[iface] = get_current_mac(iface);
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
    for (const auto& v : vendors) {
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
    if (mac.length() != 17) return false;
    
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') return false;
        } else {
            if (!std::isxdigit(mac[i])) return false;
        }
    }
    return true;
}

bool apply_mac(const std::string& iface, const std::string& new_mac) {
    // Store original first
    store_original_mac(iface);
    
    std::string old_mac = get_current_mac(iface);
    
    // Bring interface down
    auto r1 = exec::run_root("ip link set " + iface + " down");
    if (r1.code != 0) return false;
    
    // Set new MAC
    auto r2 = exec::run_root("ip link set " + iface + " address " + new_mac);
    if (r2.code != 0) {
        // Try to bring back up even if failed
        exec::run_root("ip link set " + iface + " up");
        return false;
    }
    
    // Bring interface up
    auto r3 = exec::run_root("ip link set " + iface + " up");
    
    // Add to history
    SpoofEvent event;
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&time));
    event.timestamp = buf;
    event.interface = iface;
    event.old_mac = old_mac;
    event.new_mac = new_mac;
    event.ssid = get_ssid(iface);
    add_history(event);
    
    return r3.code == 0;
}

bool restore_original(const std::string& iface) {
    std::string original = get_original_mac(iface);
    if (original.empty()) return false;
    
    return apply_mac(iface, original);
}

std::string get_ssid(const std::string& iface) {
    std::string output = exec::run("iwgetid " + iface + " -r 2>/dev/null");
    // Trim newline
    if (!output.empty() && output.back() == '\n') {
        output.pop_back();
    }
    return output.empty() ? "Not Connected" : output;
}

bool is_wifi_connected(const std::string& iface) {
    std::string ssid = get_ssid(iface);
    return !ssid.empty() && ssid != "Not Connected";
}

bool has_internet() {
    // Quick connectivity check
    auto result = exec::run("curl -s --connect-timeout 3 --max-time 5 http://captive.apple.com/hotspot-detect.html 2>/dev/null");
    return result.find("Success") != std::string::npos;
}

bool is_captive_portal() {
    auto result = exec::run("curl -s --connect-timeout 3 --max-time 5 http://captive.apple.com/hotspot-detect.html 2>/dev/null");
    
    if (result.find("Success") != std::string::npos) {
        return false;  // Normal internet
    }
    if (result.find("<html") != std::string::npos ||
        result.find("paused") != std::string::npos ||
        result.find("xfinity") != std::string::npos ||
        result.find("captive") != std::string::npos) {
        return true;  // Captive portal detected
    }
    return false;
}

void start_monitor(const std::string& iface, int interval_sec,
                   bool lock_to_network, const std::string& target_ssid,
                   bool notifications, SpoofCallback callback) {
    if (monitoring) {
        stop_monitor();
    }
    
    monitoring = true;
    
    monitor_thread = std::thread([=]() {
        bool last_connected = is_wifi_connected(iface);
        std::string last_ssid = get_ssid(iface);
        
        while (monitoring) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
            
            if (!monitoring) break;
            
            bool connected = is_wifi_connected(iface);
            std::string current_ssid = get_ssid(iface);
            
            // Reconnection detected
            if (connected && !last_connected) {
                // Check if we should spoof
                bool should_spoof = true;
                if (lock_to_network && current_ssid != target_ssid) {
                    should_spoof = false;
                }
                
                if (should_spoof) {
                    std::string new_mac = generate_random_mac();
                    if (apply_mac(iface, new_mac) && callback) {
                        SpoofEvent event;
                        event.interface = iface;
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
    monitoring = false;
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
}

bool is_monitoring() {
    return monitoring;
}

std::vector<SpoofEvent> get_history() {
    return history;
}

void add_history(const SpoofEvent& event) {
    history.insert(history.begin(), event);
    // Keep only last 50
    if (history.size() > 50) {
        history.resize(50);
    }
}

void clear_history() {
    history.clear();
}

} // namespace mac_spoofer
