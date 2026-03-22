#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>

namespace mac_spoofer {

struct SpoofEvent {
    std::string timestamp;
    std::string interface;
    std::string old_mac;
    std::string new_mac;
    std::string ssid;
};

// Vendor MAC prefixes
struct VendorPrefix {
    std::string name;
    std::string prefix;  // First 3 bytes, e.g., "00:1A:2B"
};

// Core MAC operations
std::string get_current_mac(const std::string& iface);
std::string get_original_mac(const std::string& iface);
void store_original_mac(const std::string& iface);
std::string generate_random_mac();
std::string generate_vendor_mac(const std::string& vendor);
bool is_valid_mac(const std::string& mac);
bool apply_mac(const std::string& iface, const std::string& new_mac);
bool restore_original(const std::string& iface);

// WiFi status
std::string get_ssid(const std::string& iface);
bool is_wifi_connected(const std::string& iface);
bool has_internet();
bool is_captive_portal();

// Auto-spoof monitoring
using SpoofCallback = std::function<void(const SpoofEvent&)>;
void start_monitor(const std::string& iface, int interval_sec, 
                   bool lock_to_network, const std::string& target_ssid,
                   bool notifications, SpoofCallback callback);
void stop_monitor();
bool is_monitoring();

// History
std::vector<SpoofEvent> get_history();
void add_history(const SpoofEvent& event);
void clear_history();

// Vendor list
std::vector<VendorPrefix> get_vendors();

} // namespace mac_spoofer
