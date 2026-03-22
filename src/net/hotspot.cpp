#include "hotspot.hpp"
#include "../core/security_manager.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <signal.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>

namespace hotspot {

static Config s_current_config;
static bool s_running = false;
static std::string s_last_error;
static std::mutex s_state_mutex;  // Protects s_current_config, s_running, s_last_error

// Ensure netman directory exists
static void ensure_dir() {
    std::filesystem::create_directories(NETMAN_DIR);
}

// Debug log with rotation (max 1MB)
static std::ofstream s_log;
static std::mutex s_log_mutex;
static void log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(s_log_mutex);
    ensure_dir();
    
    // Rotate log if too big (>1MB)
    if (std::filesystem::exists(HOTSPOT_LOG)) {
        try {
            auto size = std::filesystem::file_size(HOTSPOT_LOG);
            if (size > 1024 * 1024) {
                s_log.close();
                std::filesystem::remove(HOTSPOT_LOG + ".old");
                std::filesystem::rename(HOTSPOT_LOG, HOTSPOT_LOG + ".old");
            }
        } catch (...) {}
    }
    
    if (!s_log.is_open()) {
        s_log.open(HOTSPOT_LOG, std::ios::app);
        // Set restrictive permissions on log file
        std::filesystem::permissions(HOTSPOT_LOG,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    }
    s_log << "[" << time(nullptr) << "] " << msg << std::endl;
    s_log.flush();
}

std::string get_last_error() {
    return s_last_error;
}

bool check_deps() {
    return get_missing_deps().empty();
}

std::string get_missing_deps() {
    std::vector<std::string> missing;
    
    if (SEC.exec("which hostapd", false).out.empty()) {
        missing.push_back("hostapd");
    }
    if (SEC.exec("which dnsmasq", false).out.empty()) {
        missing.push_back("dnsmasq");
    }
    
    std::string result;
    for (size_t i = 0; i < missing.size(); i++) {
        if (i > 0) result += ", ";
        result += missing[i];
    }
    return result;
}

static std::string trim(const std::string& s) {
    std::string r = s;
    while (!r.empty() && (r.back() == '\n' || r.back() == '\r' || r.back() == ' ')) {
        r.pop_back();
    }
    while (!r.empty() && (r.front() == '\n' || r.front() == '\r' || r.front() == ' ')) {
        r.erase(0, 1);
    }
    return r;
}

// Use SecurityManager for all validation - these are thin wrappers for compatibility
static std::string shell_escape(const std::string& s) {
    return SEC.safe_shell(s);
}

// Safe stoi with default
static int safe_stoi(const std::string& s, int def = 0) {
    try {
        return std::stoi(s);
    } catch (...) {
        return def;
    }
}

// Thin wrappers using SecurityManager
static bool is_valid_country(const std::string& cc) {
    return SEC.validate(security::InputType::COUNTRY_CODE, cc).valid;
}

static bool is_valid_ip(const std::string& ip) {
    return SEC.validate(security::InputType::IP_ADDRESS, ip).valid;
}

static bool is_valid_channel(int ch, const std::string& band) {
    // SecurityManager validates channel standalone, we add band logic here
    auto ch_result = SEC.validate(security::InputType::CHANNEL, std::to_string(ch));
    if (!ch_result.valid) return false;
    
    if (band == "2.4") return ch >= 1 && ch <= 14;
    if (band == "5") return ch >= 36;
    return false;
}

static bool is_valid_band(const std::string& band) {
    return SEC.validate(security::InputType::BAND, band).valid;
}

static std::string config_escape(const std::string& s) {
    // For config files, use SSID validation (printable ASCII)
    auto result = SEC.validate(security::InputType::SSID, s);
    return result.valid ? result.sanitized : "";
}

static bool is_valid_mac(const std::string& mac) {
    return SEC.validate(security::InputType::MAC_ADDRESS, mac).valid;
}

static std::string sanitize_hostname(const std::string& h) {
    auto result = SEC.validate(security::InputType::HOSTNAME, h);
    return result.valid ? result.sanitized : "";
}

std::vector<std::string> get_ap_capable_interfaces() {
    std::vector<std::string> result;
    std::vector<std::string> wifi_ifaces;
    
    // Method 1: Check /sys/class/net/*/wireless (most reliable)
    auto sys_output = SEC.exec("ls -d /sys/class/net/*/wireless 2>/dev/null | cut -d'/' -f5", false).out;
    std::istringstream sys_iss(sys_output);
    std::string iface;
    while (std::getline(sys_iss, iface)) {
        iface = trim(iface);
        if (!iface.empty()) {
            wifi_ifaces.push_back(iface);
        }
    }
    
    // Method 2: Fallback to iw dev
    if (wifi_ifaces.empty()) {
        auto iw_output = SEC.exec("iw dev 2>/dev/null | grep Interface | awk '{print $2}'", false).out;
        std::istringstream iw_iss(iw_output);
        while (std::getline(iw_iss, iface)) {
            iface = trim(iface);
            if (!iface.empty()) {
                wifi_ifaces.push_back(iface);
            }
        }
    }
    
    // Method 3: Fallback to iwconfig
    if (wifi_ifaces.empty()) {
        auto iwc_output = SEC.exec("iwconfig 2>/dev/null | grep -v 'no wireless' | grep -E '^[a-z]' | awk '{print $1}'", false).out;
        std::istringstream iwc_iss(iwc_output);
        while (std::getline(iwc_iss, iface)) {
            iface = trim(iface);
            if (!iface.empty()) {
                wifi_ifaces.push_back(iface);
            }
        }
    }
    
    // Check each interface for AP mode support
    for (const auto& wif : wifi_ifaces) {
        std::string safe_wif = shell_escape(wif);
        if (safe_wif.empty()) continue;  // Skip invalid names
        
        // Get phy number
        auto phy = SEC.exec("iw dev " + safe_wif + " info 2>/dev/null | grep wiphy | awk '{print $2}'", false).out;
        phy = trim(phy);
        
        if (phy.empty()) {
            // Can't verify AP mode, but include it anyway with warning
            result.push_back(safe_wif);
            continue;
        }
        
        // Sanitize phy number (should be digits only)
        std::string safe_phy;
        for (char c : phy) {
            if (std::isdigit(c)) safe_phy += c;
        }
        if (safe_phy.empty()) {
            result.push_back(safe_wif);
            continue;
        }
        
        // Check for AP mode support
        auto modes = SEC.exec("iw phy phy" + safe_phy + " info 2>/dev/null | grep -E '^\\s+\\* AP$'", false).out;
        if (!modes.empty()) {
            result.push_back(safe_wif);
        } else {
            // Broader check
            modes = SEC.exec("iw phy phy" + safe_phy + " info 2>/dev/null | grep -i 'AP'", false).out;
            if (modes.find("* AP") != std::string::npos) {
                result.push_back(safe_wif);
            } else {
                // Include anyway, let hostapd fail if it doesn't work
                result.push_back(safe_wif);
            }
        }
    }
    
    return result;
}

bool supports_5ghz(const std::string& iface) {
    std::string safe_iface = shell_escape(iface);
    if (safe_iface.empty()) return true;  // Assume yes if can't check
    
    // Method 1: Check via iw phy
    auto phy = SEC.exec("iw dev " + safe_iface + " info 2>/dev/null | grep wiphy | awk '{print $2}'", false).out;
    phy = trim(phy);
    
    // Sanitize phy
    std::string safe_phy;
    for (char c : phy) {
        if (std::isdigit(c)) safe_phy += c;
    }
    
    if (!safe_phy.empty()) {
        // Check for 5GHz frequencies (5000-5999 MHz)
        auto freqs = SEC.exec("iw phy phy" + safe_phy + " info 2>/dev/null | grep -E '5[0-9]{3}'", false).out;
        if (!freqs.empty()) return true;
        
        // Check for "Band 2" which is typically 5GHz
        auto band = SEC.exec("iw phy phy" + safe_phy + " info 2>/dev/null | grep -i 'Band 2'", false).out;
        if (!band.empty()) return true;
    }
    
    // Method 2: Check via iw list
    auto iw_list = SEC.exec("iw list 2>/dev/null | grep -A 50 'Wiphy' | grep -E '5[0-9]{3}'", false).out;
    if (!iw_list.empty()) return true;
    
    // Method 3: Assume true if we can't determine (let hostapd fail gracefully)
    return true;
}

bool start(const Config& cfg) {
    log("=== Starting hotspot ===");
    log("Interface: " + cfg.interface);
    log("SSID: " + cfg.ssid);
    log("Band: " + cfg.band + " Channel: " + std::to_string(cfg.channel));
    
    // Stop any existing instance
    stop();
    
    // Validate
    if (cfg.interface.empty() || cfg.ssid.empty()) {
        s_last_error = "Interface or SSID empty";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (cfg.ssid.length() > 32) {
        s_last_error = "SSID too long (max 32 chars)";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (cfg.password.length() < 8 && !cfg.password.empty()) {
        s_last_error = "Password must be 8+ chars";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (cfg.password.length() > 63) {
        s_last_error = "Password too long (max 63 chars)";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (!is_valid_country(cfg.country_code)) {
        s_last_error = "Invalid country code";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (!is_valid_ip(cfg.ap_ip) || !is_valid_ip(cfg.dhcp_start) || !is_valid_ip(cfg.dhcp_end)) {
        s_last_error = "Invalid IP address format";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (!is_valid_band(cfg.band)) {
        s_last_error = "Invalid band (must be 2.4 or 5)";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (!is_valid_channel(cfg.channel, cfg.band)) {
        s_last_error = "Invalid channel for band";
        log("ERROR: " + s_last_error);
        return false;
    }
    
    // Sanitize inputs - use SEC validators and keep sanitized results
    std::string safe_iface = SEC.safe_interface(cfg.interface);
    std::string safe_ssid = SEC.safe_ssid(cfg.ssid);
    std::string safe_pass = SEC.safe_password(cfg.password);
    std::string safe_share = cfg.share_from.empty() ? "" : SEC.safe_interface(cfg.share_from);
    
    // Get sanitized versions (normalized)
    auto ap_ip_result = SEC.validate(security::InputType::IP_ADDRESS, cfg.ap_ip);
    auto dhcp_start_result = SEC.validate(security::InputType::IP_ADDRESS, cfg.dhcp_start);
    auto dhcp_end_result = SEC.validate(security::InputType::IP_ADDRESS, cfg.dhcp_end);
    auto country_result = SEC.validate(security::InputType::COUNTRY_CODE, cfg.country_code);
    
    std::string safe_ap_ip = ap_ip_result.sanitized;
    std::string safe_dhcp_start = dhcp_start_result.sanitized;
    std::string safe_dhcp_end = dhcp_end_result.sanitized;
    std::string safe_country = country_result.sanitized;
    
    // Band and channel (already validated above, use directly)
    std::string safe_band = cfg.band;  // "2.4" or "5" only
    int safe_channel = cfg.channel;    // Validated channel number
    
    // Verify sanitization didn't empty critical values
    if (safe_iface.empty() || safe_ssid.empty()) {
        s_last_error = "Interface or SSID contains only invalid characters";
        log("ERROR: " + s_last_error);
        return false;
    }
    if (!cfg.password.empty() && safe_pass.empty()) {
        s_last_error = "Password contains only invalid characters";
        log("ERROR: " + s_last_error);
        return false;
    }
    
    // === CRITICAL: Release interface from other managers ===
    log("Releasing interface from NetworkManager...");
    
    // Stop NetworkManager from managing this interface
    auto nm_result = SEC.exec("nmcli device set " + safe_iface + " managed no 2>&1", false).out;
    log("nmcli result: " + nm_result);
    
    // Kill wpa_supplicant ONLY for this interface (not all!)
    SEC.exec("pkill -f 'wpa_supplicant.*-i" + safe_iface + "' 2>/dev/null", false).out;
    SEC.exec("pkill -f 'wpa_supplicant.*" + safe_iface + "' 2>/dev/null", false).out;
    
    // Small delay for processes to die
    SEC.exec("sleep 0.5", false).out;
    
    // Bring down interface
    log("Bringing down interface...");
    SEC.exec("ip link set " + safe_iface + " down", false).out;
    SEC.exec("ip addr flush dev " + safe_iface, false).out;
    
    // Set interface type
    SEC.exec("iw dev " + safe_iface + " set type managed 2>/dev/null", false).out;
    
    // Set static IP for AP
    log("Setting IP " + safe_ap_ip + "...");
    auto ip_result = SEC.exec("ip addr add " + safe_ap_ip + "/24 dev " + safe_iface + " 2>&1", false).out;
    log("ip addr result: " + ip_result);
    
    SEC.exec("ip link set " + safe_iface + " up", false).out;
    
    // Verify interface is up
    auto link_state = SEC.exec("ip link show " + safe_iface + " 2>&1", false).out;
    log("Link state: " + link_state);
    
    // Set regulatory domain (required for 5GHz AP mode)
    log("Setting regulatory domain to " + safe_country);
    SEC.exec("iw reg set " + safe_country + " 2>&1", false).out;
    SEC.exec("sleep 0.3", false).out;
    
    // Generate hostapd config
    log("Writing hostapd config to " + HOSTAPD_CONF);
    ensure_dir();
    std::ofstream hconf(HOSTAPD_CONF);
    if (!hconf.is_open()) {
        s_last_error = "Failed to create hostapd config file";
        log("ERROR: " + s_last_error);
        return false;
    }
    hconf << "interface=" << safe_iface << "\n";
    hconf << "driver=nl80211\n";
    hconf << "ssid=" << safe_ssid << "\n";
    hconf << "country_code=" << safe_country << "\n";
    hconf << "ieee80211d=1\n";  // Advertise country code
    hconf << "hw_mode=" << (safe_band == "5" ? "a" : "g") << "\n";
    hconf << "channel=" << safe_channel << "\n";
    hconf << "ieee80211n=1\n";
    if (safe_band == "5") {
        hconf << "ieee80211ac=1\n";
    }
    hconf << "wmm_enabled=1\n";
    hconf << "ignore_broadcast_ssid=" << (cfg.hidden ? "1" : "0") << "\n";
    
    if (!safe_pass.empty()) {
        hconf << "auth_algs=1\n";
        hconf << "wpa=2\n";
        hconf << "wpa_key_mgmt=WPA-PSK\n";
        hconf << "wpa_pairwise=CCMP\n";
        hconf << "rsn_pairwise=CCMP\n";
        hconf << "wpa_passphrase=" << safe_pass << "\n";
    }
    hconf.close();
    
    if (hconf.fail()) {
        s_last_error = "Failed to write hostapd config";
        log("ERROR: " + s_last_error);
        return false;
    }
    
    // Set restrictive permissions on config (contains password)
    std::filesystem::permissions(HOSTAPD_CONF, 
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    
    // Log config (without password)
    log("hostapd.conf written (password redacted)");
    
    // Generate dnsmasq config
    log("Writing dnsmasq config to " + DNSMASQ_CONF);
    std::ofstream dconf(DNSMASQ_CONF);
    if (!dconf.is_open()) {
        s_last_error = "Failed to create dnsmasq config file";
        log("ERROR: " + s_last_error);
        return false;
    }
    dconf << "interface=" << safe_iface << "\n";
    dconf << "bind-interfaces\n";
    dconf << "dhcp-range=" << safe_dhcp_start << "," << safe_dhcp_end << ",24h\n";
    dconf << "dhcp-option=option:router," << safe_ap_ip << "\n";
    dconf << "dhcp-option=option:dns-server,8.8.8.8,8.8.4.4\n";
    dconf << "dhcp-leasefile=" << DNSMASQ_LEASES << "\n";
    dconf.close();
    
    if (dconf.fail()) {
        s_last_error = "Failed to write dnsmasq config";
        log("ERROR: " + s_last_error);
        return false;
    }
    
    // Start hostapd (foreground briefly to capture output)
    log("Starting hostapd...");
    auto hostapd_cmd = "hostapd -B -P " + HOSTAPD_PID + " " + HOSTAPD_CONF + " 2>&1";
    log("Command: " + hostapd_cmd);
    auto hostapd_result = SEC.exec(hostapd_cmd, false).out;
    log("hostapd output: " + hostapd_result);
    
    // Wait for it to start
    SEC.exec("sleep 1", false).out;
    
    // Check if hostapd started
    if (!std::filesystem::exists(HOSTAPD_PID)) {
        // Try to get more info
        auto ps = SEC.exec("ps aux | grep hostapd", false).out;
        log("hostapd processes: " + ps);
        
        s_last_error = "hostapd failed to start: " + hostapd_result;
        log("ERROR: " + s_last_error);
        return false;
    }
    
    auto hostapd_pid = SEC.exec("cat " + HOSTAPD_PID, false).out;
    log("hostapd started with PID: " + hostapd_pid);
    
    // Start dnsmasq
    log("Starting dnsmasq...");
    auto dnsmasq_result = SEC.exec("dnsmasq -C " + DNSMASQ_CONF + " --pid-file=" + DNSMASQ_PID + " 2>&1", false).out;
    log("dnsmasq output: " + dnsmasq_result);
    
    // Verify dnsmasq started
    SEC.exec("sleep 0.5", false).out;
    if (!std::filesystem::exists(DNSMASQ_PID)) {
        log("WARNING: dnsmasq may have failed to start");
        // Don't fail - hotspot can work without DHCP if clients use static IP
    }
    
    // Enable NAT if sharing internet
    if (!safe_share.empty()) {
        log("Enabling NAT from " + safe_share);
        enable_nat(safe_iface, safe_share);
    }
    
    s_current_config = cfg;
    s_running = true;
    log("=== Hotspot started successfully ===");
    return true;
}

bool stop() {
    std::string iface = shell_escape(s_current_config.interface);
    
    // Kill hostapd
    if (std::filesystem::exists(HOSTAPD_PID)) {
        std::ifstream pf(HOSTAPD_PID);
        std::string pid_str;
        std::getline(pf, pid_str);
        int pid = safe_stoi(pid_str, 0);
        if (pid > 0) {
            kill(pid, SIGTERM);
        }
        std::filesystem::remove(HOSTAPD_PID);
    }
    
    // Also kill by name in case PID file is stale
    SEC.exec("pkill -f 'hostapd.*netman' 2>/dev/null", false).out;
    
    // Kill dnsmasq
    if (std::filesystem::exists(DNSMASQ_PID)) {
        std::ifstream pf(DNSMASQ_PID);
        std::string pid_str;
        std::getline(pf, pid_str);
        int pid = safe_stoi(pid_str, 0);
        if (pid > 0) {
            kill(pid, SIGTERM);
        }
        std::filesystem::remove(DNSMASQ_PID);
    }
    
    SEC.exec("pkill -f 'dnsmasq.*netman' 2>/dev/null", false).out;
    
    // Disable NAT (sanitize inputs)
    if (!s_current_config.share_from.empty()) {
        std::string safe_share = shell_escape(s_current_config.share_from);
        disable_nat(iface, safe_share);
    }
    
    // Cleanup config files
    std::filesystem::remove(HOSTAPD_CONF);
    std::filesystem::remove(DNSMASQ_CONF);
    
    // === Restore interface to NetworkManager ===
    if (!iface.empty()) {
        // Bring down and reset
        SEC.exec("ip link set " + iface + " down 2>/dev/null", false).out;
        SEC.exec("ip addr flush dev " + iface + " 2>/dev/null", false).out;
        
        // Return to managed mode
        SEC.exec("iw dev " + iface + " set type managed 2>/dev/null", false).out;
        
        // Give back to NetworkManager
        SEC.exec("nmcli device set " + iface + " managed yes 2>/dev/null", false).out;
        
        // Restart wpa_supplicant for this interface
        SEC.exec("systemctl restart wpa_supplicant 2>/dev/null", false).out;
        
        // Bring interface back up
        SEC.exec("ip link set " + iface + " up 2>/dev/null", false).out;
    }
    
    s_running = false;
    s_current_config = Config{};
    return true;
}

bool is_running() {
    // Check if hostapd is actually running
    if (!std::filesystem::exists(HOSTAPD_PID)) {
        s_running = false;
        return false;
    }
    
    std::ifstream pf(HOSTAPD_PID);
    std::string pid_str;
    std::getline(pf, pid_str);
    
    int pid = safe_stoi(pid_str, 0);
    if (pid <= 0) {
        s_running = false;
        return false;
    }
    
    // Check if process exists
    if (kill(pid, 0) != 0) {
        s_running = false;
        return false;
    }
    
    s_running = true;
    return true;
}

Config get_current_config() {
    return s_current_config;
}

// Convert dBm to percentage (rough approximation)
static int dbm_to_percent(int dbm) {
    // Typical range: -90 dBm (weak) to -30 dBm (strong)
    if (dbm >= -30) return 100;
    if (dbm <= -90) return 0;
    return (dbm + 90) * 100 / 60;
}

std::vector<Client> get_clients() {
    std::vector<Client> result;
    
    if (!is_running()) return result;
    
    std::string iface = shell_escape(s_current_config.interface);
    log("get_clients: interface = " + iface);
    
    // Try hostapd_cli first (comes with hostapd), then iw as fallback
    // Use timeout to prevent blocking
    auto station_dump = SEC.exec("timeout 2 hostapd_cli -i " + iface + " all_sta 2>&1", false).out;
    
    // If hostapd_cli fails, try iw
    if (station_dump.empty() ||
        station_dump.find("not found") != std::string::npos || 
        station_dump.find("Failed to connect") != std::string::npos ||
        station_dump.find("No such file") != std::string::npos ||
        station_dump.find("timed out") != std::string::npos) {
        log("hostapd_cli failed, trying iw");
        station_dump = SEC.exec("timeout 2 /usr/sbin/iw dev " + iface + " station dump 2>&1", false).out;
    }
    
    log("station dump output:\n" + station_dump);
    
    // Parse station dump (handles both iw and hostapd_cli formats)
    std::istringstream ss(station_dump);
    std::string line;
    Client current;
    bool in_station = false;
    
    while (std::getline(ss, line)) {
        // iw format: "Station aa:bb:cc:dd:ee:ff (on wlan0)"
        if (line.find("Station ") == 0) {
            if (in_station && !current.mac.empty() && is_valid_mac(current.mac)) {
                current.connected = true;
                result.push_back(current);
            }
            current = Client{};
            in_station = true;
            
            size_t start = 8;
            size_t end = line.find(" ", start);
            if (end != std::string::npos) {
                std::string mac_candidate = line.substr(start, end - start);
                if (is_valid_mac(mac_candidate)) {
                    current.mac = mac_candidate;
                }
            }
        }
        // hostapd_cli format: MAC address on its own line (aa:bb:cc:dd:ee:ff)
        else if (line.length() == 17 && is_valid_mac(line)) {
            if (in_station && !current.mac.empty() && is_valid_mac(current.mac)) {
                current.connected = true;
                result.push_back(current);
            }
            current = Client{};
            current.mac = line;
            in_station = true;
        }
        else if (in_station) {
            // Parse station info (works for both formats)
            // iw: "	signal:  -45 dBm" or "	signal avg:	-45 dBm"
            // hostapd_cli: "signal=-45"
            if (line.find("signal") != std::string::npos && line.find("avg") == std::string::npos) {
                size_t pos = line.find("=");
                if (pos == std::string::npos) pos = line.find(":");
                if (pos != std::string::npos) {
                    try {
                        std::string val = line.substr(pos + 1);
                        // Remove leading whitespace and trailing text
                        size_t start = val.find_first_not_of(" \t");
                        if (start != std::string::npos) {
                            val = val.substr(start);
                        }
                        current.signal = std::stoi(val);
                        current.signal_percent = dbm_to_percent(current.signal);
                    } catch (...) {}
                }
            }
            else if (line.find("rx bytes") != std::string::npos) {
                size_t pos = line.find(":");
                if (pos == std::string::npos) pos = line.find("=");
                if (pos != std::string::npos) {
                    try {
                        current.rx_bytes = std::stoull(line.substr(pos + 1));
                    } catch (...) {}
                }
            }
            else if (line.find("tx bytes") != std::string::npos) {
                size_t pos = line.find(":");
                if (pos == std::string::npos) pos = line.find("=");
                if (pos != std::string::npos) {
                    try {
                        current.tx_bytes = std::stoull(line.substr(pos + 1));
                    } catch (...) {}
                }
            }
        }
    }
    
    // Don't forget last station
    if (in_station && !current.mac.empty() && is_valid_mac(current.mac)) {
        current.connected = true;
        result.push_back(current);
    }
    
    log("Found " + std::to_string(result.size()) + " connected stations");
    for (const auto& c : result) {
        log("  Station: " + c.mac + " signal=" + std::to_string(c.signal));
    }
    
    // Cross-reference with dnsmasq leases for IP/hostname
    if (std::filesystem::exists(DNSMASQ_LEASES)) {
        std::ifstream lf(DNSMASQ_LEASES);
        while (std::getline(lf, line)) {
            std::istringstream iss(line);
            std::string timestamp, mac, ip, hostname;
            iss >> timestamp >> mac >> ip >> hostname;
            
            // Validate lease data
            if (!is_valid_mac(mac)) continue;
            if (!is_valid_ip(ip)) continue;
            
            // Convert MAC to lowercase for comparison
            std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
            
            for (auto& client : result) {
                std::string client_mac = client.mac;
                std::transform(client_mac.begin(), client_mac.end(), client_mac.begin(), ::tolower);
                
                if (client_mac == mac) {
                    client.ip = ip;
                    client.hostname = sanitize_hostname((hostname == "*") ? "" : hostname);
                    break;
                }
            }
        }
    }
    
    return result;
}

bool enable_nat(const std::string& ap_iface, const std::string& wan_iface) {
    // Enable IP forwarding
    SEC.exec("echo 1 > /proc/sys/net/ipv4/ip_forward", false).out;
    
    // Remove existing rules first to prevent duplicates
    disable_nat(ap_iface, wan_iface);
    
    // Setup NAT
    SEC.exec("iptables -t nat -A POSTROUTING -o " + wan_iface + " -j MASQUERADE", false).out;
    SEC.exec("iptables -A FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT", false).out;
    SEC.exec("iptables -A FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT", false).out;
    
    return true;
}

bool disable_nat(const std::string& ap_iface, const std::string& wan_iface) {
    SEC.exec("iptables -t nat -D POSTROUTING -o " + wan_iface + " -j MASQUERADE 2>/dev/null", false).out;
    SEC.exec("iptables -D FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT 2>/dev/null", false).out;
    SEC.exec("iptables -D FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null", false).out;
    
    return true;
}

std::vector<ChannelInfo> scan_channels(const std::string& iface) {
    std::vector<ChannelInfo> result;
    std::string safe_iface = shell_escape(iface);
    log("Scanning channels on " + safe_iface);
    
    // Use iwlist or iw to scan
    auto scan_output = SEC.exec("timeout 10 iwlist " + safe_iface + " scan 2>/dev/null", false).out;
    
    if (scan_output.empty() || scan_output.find("not found") != std::string::npos) {
        // Try iw instead
        scan_output = SEC.exec("timeout 10 /usr/sbin/iw dev " + safe_iface + " scan 2>/dev/null", false).out;
    }
    
    // Count networks per channel
    std::map<int, int> channel_counts;
    
    // Initialize common channels
    // 2.4GHz: 1-11
    for (int i = 1; i <= 11; i++) channel_counts[i] = 0;
    // 5GHz common channels
    for (int ch : {36, 40, 44, 48, 149, 153, 157, 161}) channel_counts[ch] = 0;
    
    std::istringstream ss(scan_output);
    std::string line;
    
    while (std::getline(ss, line)) {
        // iwlist format: "Channel:6"
        size_t pos = line.find("Channel:");
        if (pos != std::string::npos) {
            try {
                int ch = std::stoi(line.substr(pos + 8));
                channel_counts[ch]++;
            } catch (...) {}
        }
        // iw format: "DS Parameter set: channel 6"
        pos = line.find("channel ");
        if (pos != std::string::npos) {
            try {
                int ch = std::stoi(line.substr(pos + 8));
                channel_counts[ch]++;
            } catch (...) {}
        }
    }
    
    for (const auto& [ch, count] : channel_counts) {
        ChannelInfo info;
        info.channel = ch;
        info.networks = count;
        // Approximate frequency
        if (ch <= 14) {
            info.frequency = 2407 + ch * 5;
        } else {
            info.frequency = 5000 + ch * 5;
        }
        result.push_back(info);
    }
    
    log("Found " + std::to_string(result.size()) + " channels");
    return result;
}

int find_best_channel(const std::string& iface, const std::string& band) {
    auto channels = scan_channels(iface);
    
    int best_channel = (band == "5") ? 36 : 6;  // Defaults
    int min_networks = 999;
    
    for (const auto& ch : channels) {
        // Filter by band
        bool is_5ghz = (ch.channel >= 36);
        if ((band == "5" && !is_5ghz) || (band == "2.4" && is_5ghz)) {
            continue;
        }
        
        // For 2.4GHz, prefer non-overlapping channels (1, 6, 11)
        if (band == "2.4" && ch.channel != 1 && ch.channel != 6 && ch.channel != 11) {
            continue;
        }
        
        if (ch.networks < min_networks) {
            min_networks = ch.networks;
            best_channel = ch.channel;
        }
    }
    
    log("Best channel for " + band + "GHz: " + std::to_string(best_channel) + 
        " (" + std::to_string(min_networks) + " networks)");
    
    return best_channel;
}

} // namespace hotspot
