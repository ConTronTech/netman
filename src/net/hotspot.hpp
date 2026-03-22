#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace hotspot {

struct Client {
    std::string mac;
    std::string ip;
    std::string hostname;
    int signal = 0;         // dBm (negative, e.g. -45)
    int signal_percent = 0; // 0-100%
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
    bool connected = false; // Currently associated
};

struct Config {
    std::string interface;      // WiFi interface to use as AP
    std::string ssid;
    std::string password;       // Min 8 chars for WPA2
    int channel = 6;            // 1-11 for 2.4GHz, 36+ for 5GHz
    std::string band = "2.4";   // "2.4" or "5"
    std::string share_from;     // Interface to share internet from (NAT)
    std::string country_code = "US";  // Regulatory domain (required for 5GHz)
    std::string ap_ip = "192.168.50.1";  // AP IP address
    std::string dhcp_start = "192.168.50.10";  // DHCP range start
    std::string dhcp_end = "192.168.50.254";   // DHCP range end
    bool hidden = false;
};

// Check if dependencies are installed
bool check_deps();
std::string get_missing_deps();

// Get WiFi interfaces that support AP mode
std::vector<std::string> get_ap_capable_interfaces();

// Check if interface supports 5GHz
bool supports_5ghz(const std::string& iface);

// Hotspot control
bool start(const Config& cfg);
bool stop();
bool is_running();
std::string get_last_error();

// Get current config (if running)
Config get_current_config();

// Connected clients
std::vector<Client> get_clients();

// NAT helpers
bool enable_nat(const std::string& ap_iface, const std::string& wan_iface);
bool disable_nat(const std::string& ap_iface, const std::string& wan_iface);

// Config file paths (all in /tmp/netman/)
const std::string NETMAN_DIR = "/tmp/netman";
const std::string HOSTAPD_CONF = "/tmp/netman/hostapd.conf";
const std::string DNSMASQ_CONF = "/tmp/netman/dnsmasq.conf";
const std::string HOSTAPD_PID = "/tmp/netman/hostapd.pid";
const std::string DNSMASQ_PID = "/tmp/netman/dnsmasq.pid";
const std::string DNSMASQ_LEASES = "/tmp/netman/dnsmasq.leases";
const std::string HOTSPOT_LOG = "/tmp/netman/hotspot.log";

// Channel scanning
struct ChannelInfo {
    int channel;
    int frequency;
    int networks;  // Number of networks on this channel
};

std::vector<ChannelInfo> scan_channels(const std::string& iface);
int find_best_channel(const std::string& iface, const std::string& band);

} // namespace hotspot
