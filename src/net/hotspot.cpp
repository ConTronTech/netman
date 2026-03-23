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
#include <thread>
#include <chrono>

namespace hotspot {

static Config s_current_config;
static bool s_running = false;
static std::string s_last_error;
static std::mutex s_state_mutex;  // Protects s_current_config, s_running, s_last_error

// Thread-safe state setters
static void set_error(const std::string& err) {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_last_error = err;
}

static void set_running(bool running) {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_running = running;
}

static void set_config(const Config& cfg) {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_current_config = cfg;
}

static void clear_state() {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    s_running = false;
    s_current_config = Config{};
}

// Ensure netman directory exists and is secure
static bool ensure_dir() {
    namespace fs = std::filesystem;
    
    // If directory exists, verify it's not a symlink
    if (fs::exists(NETMAN_DIR)) {
        if (fs::is_symlink(NETMAN_DIR)) {
            // Symlink attack - refuse to use
            return false;
        }
    } else {
        fs::create_directories(NETMAN_DIR);
    }
    
    // Set restrictive permissions (owner only)
    fs::permissions(NETMAN_DIR, 
        fs::perms::owner_all,
        fs::perm_options::replace);
    
    return true;
}

// Check if a file path is safe (not a symlink)
static bool is_safe_file_path(const std::string& path) {
    namespace fs = std::filesystem;
    if (fs::exists(path) && fs::is_symlink(path)) {
        return false;  // Symlink attack
    }
    return true;
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
    std::lock_guard<std::mutex> lock(s_state_mutex);
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
    
    // Method 1: Check /sys/class/net directly (no shell pipes)
    try {
        for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net")) {
            std::string name = entry.path().filename().string();
            // Check if wireless subdir exists
            if (std::filesystem::exists(entry.path() / "wireless")) {
                wifi_ifaces.push_back(name);
            }
        }
    } catch (...) {}
    
    // Method 2: Fallback to iw dev (parse output in C++)
    if (wifi_ifaces.empty()) {
        auto iw_output = SEC.exec("iw dev", false).out;
        std::istringstream iw_iss(iw_output);
        std::string line;
        while (std::getline(iw_iss, line)) {
            // Look for "Interface wlan0" lines
            size_t pos = line.find("Interface ");
            if (pos != std::string::npos) {
                std::string iface = trim(line.substr(pos + 10));
                if (!iface.empty()) {
                    wifi_ifaces.push_back(iface);
                }
            }
        }
    }
    
    // Method 3: Fallback to iwconfig (parse output in C++)
    if (wifi_ifaces.empty()) {
        auto iwc_output = SEC.exec("iwconfig", false).out;
        std::istringstream iwc_iss(iwc_output);
        std::string line;
        while (std::getline(iwc_iss, line)) {
            // Lines starting with interface name (not whitespace) that don't say "no wireless"
            if (!line.empty() && !std::isspace(line[0]) && line.find("no wireless") == std::string::npos) {
                std::istringstream lss(line);
                std::string iface;
                lss >> iface;
                if (!iface.empty()) {
                    wifi_ifaces.push_back(iface);
                }
            }
        }
    }
    
    // Check each interface for AP mode support
    for (const auto& wif : wifi_ifaces) {
        std::string safe_wif = SEC.safe_interface(wif);
        if (safe_wif.empty()) continue;  // Skip invalid names
        
        // Get phy number (parse iw output in C++)
        auto iw_info = SEC.exec("iw dev " + safe_wif + " info", false).out;
        std::string phy;
        size_t wiphy_pos = iw_info.find("wiphy ");
        if (wiphy_pos != std::string::npos) {
            std::istringstream pss(iw_info.substr(wiphy_pos + 6));
            pss >> phy;
        }
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
        
        // Check for AP mode support (parse output in C++)
        auto phy_info = SEC.exec("iw phy phy" + safe_phy + " info", false).out;
        if (phy_info.find("* AP") != std::string::npos) {
            result.push_back(safe_wif);
        } else {
            // Include anyway, let hostapd fail if it doesn't work
            result.push_back(safe_wif);
        }
    }
    
    return result;
}

bool supports_5ghz(const std::string& iface) {
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return true;  // Assume yes if can't check
    
    // Get phy number (parse output in C++)
    auto iw_info = SEC.exec("iw dev " + safe_iface + " info", false).out;
    std::string phy;
    size_t wiphy_pos = iw_info.find("wiphy ");
    if (wiphy_pos != std::string::npos) {
        std::istringstream pss(iw_info.substr(wiphy_pos + 6));
        pss >> phy;
    }
    phy = trim(phy);
    
    // Sanitize phy
    std::string safe_phy;
    for (char c : phy) {
        if (std::isdigit(c)) safe_phy += c;
    }
    
    if (!safe_phy.empty()) {
        // Check for 5GHz frequencies (5000-5999 MHz) in phy info
        auto phy_info = SEC.exec("iw phy phy" + safe_phy + " info", false).out;
        // Look for frequencies in 5xxx range
        if (phy_info.find("5180") != std::string::npos ||
            phy_info.find("5240") != std::string::npos ||
            phy_info.find("5745") != std::string::npos ||
            phy_info.find("Band 2") != std::string::npos) {
            return true;
        }
    }
    
    // Method 2: Check via iw list (parse in C++)
    auto iw_list = SEC.exec("iw list", false).out;
    if (iw_list.find("5180") != std::string::npos ||
        iw_list.find("5240") != std::string::npos ||
        iw_list.find("5745") != std::string::npos) {
        return true;
    }
    
    // Assume true if we can't determine (let hostapd fail gracefully)
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
    auto nm_result = SEC.exec("nmcli device set " + safe_iface + " managed no", false).out;
    log("nmcli result: " + nm_result);
    
    // Kill wpa_supplicant for this interface via PID file if exists
    std::string wpa_pid_file = "/tmp/netman/wpa_" + safe_iface + ".pid";
    if (std::filesystem::exists(wpa_pid_file)) {
        SEC.exec("pkill -F " + wpa_pid_file, false);
        std::filesystem::remove(wpa_pid_file);
    }
    // Also try systemctl as fallback (safer than grep-based pkill)
    SEC.exec("systemctl stop wpa_supplicant", false);
    
    // Small delay for processes to die
    SEC.exec("sleep 0.5", false).out;
    
    // Bring down interface
    log("Bringing down interface...");
    SEC.exec("ip link set " + safe_iface + " down", false).out;
    SEC.exec("ip addr flush dev " + safe_iface, false).out;
    
    // Set interface type
    SEC.exec("iw dev " + safe_iface + " set type managed", false).out;
    
    // Set static IP for AP
    log("Setting IP " + safe_ap_ip + "...");
    auto ip_result = SEC.exec("ip addr add " + safe_ap_ip + "/24 dev " + safe_iface + "", false).out;
    log("ip addr result: " + ip_result);
    
    SEC.exec("ip link set " + safe_iface + " up", false).out;
    
    // Verify interface is up
    auto link_state = SEC.exec("ip link show " + safe_iface + "", false).out;
    log("Link state: " + link_state);
    
    // Set regulatory domain (required for 5GHz AP mode)
    log("Setting regulatory domain to " + safe_country);
    SEC.exec("iw reg set " + safe_country + "", false).out;
    SEC.exec("sleep 0.3", false).out;
    
    // Generate hostapd config
    log("Writing hostapd config to " + HOSTAPD_CONF);
    if (!ensure_dir()) {
        s_last_error = "Security: /tmp/netman is a symlink";
        log("ERROR: " + s_last_error);
        return false;
    }
    // Check for symlink attack on config file
    if (!is_safe_file_path(HOSTAPD_CONF)) {
        s_last_error = "Security: config file is a symlink";
        log("ERROR: " + s_last_error);
        return false;
    }
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
    if (!is_safe_file_path(DNSMASQ_CONF)) {
        s_last_error = "Security: dnsmasq config is a symlink";
        log("ERROR: " + s_last_error);
        return false;
    }
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
    auto hostapd_cmd = "hostapd -B -P " + HOSTAPD_PID + " " + HOSTAPD_CONF + "";
    log("Command: " + hostapd_cmd);
    auto hostapd_result = SEC.exec(hostapd_cmd, false).out;
    log("hostapd output: " + hostapd_result);
    
    // Wait for it to start
    SEC.exec("sleep 1", false).out;
    
    // Check if hostapd started
    if (!std::filesystem::exists(HOSTAPD_PID)) {
        // Try to get more info using pgrep (no pipes needed)
        auto ps = SEC.exec("pgrep -a hostapd", false).out;
        log("hostapd processes: " + ps);
        
        s_last_error = "hostapd failed to start: " + hostapd_result;
        log("ERROR: " + s_last_error);
        return false;
    }
    
    auto hostapd_pid = SEC.exec("cat " + HOSTAPD_PID, false).out;
    log("hostapd started with PID: " + hostapd_pid);
    
    // Start dnsmasq
    log("Starting dnsmasq...");
    auto dnsmasq_result = SEC.exec("dnsmasq -C " + DNSMASQ_CONF + " --pid-file=" + DNSMASQ_PID + "", false).out;
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
    
    set_config(cfg);
    set_running(true);
    log("=== Hotspot started successfully ===");
    return true;
}

bool stop() {
    std::string safe_iface = SEC.safe_interface(s_current_config.interface);
    
    // Kill hostapd via PID file (the ONLY safe way)
    if (std::filesystem::exists(HOSTAPD_PID)) {
        // Use pkill -F which reads PID from file
        SEC.exec("pkill -F " + HOSTAPD_PID, false);
        // Small delay for process to die
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // Clean up PID file
        std::filesystem::remove(HOSTAPD_PID);
    }
    // Fallback: use systemctl (no pattern matching)
    SEC.exec("systemctl stop hostapd", false);
    
    // Kill dnsmasq via PID file
    if (std::filesystem::exists(DNSMASQ_PID)) {
        SEC.exec("pkill -F " + DNSMASQ_PID, false);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::filesystem::remove(DNSMASQ_PID);
    }
    SEC.exec("systemctl stop dnsmasq", false);
    
    // Disable NAT (sanitize inputs)
    if (!s_current_config.share_from.empty()) {
        std::string safe_share = SEC.safe_interface(s_current_config.share_from);
        if (!safe_share.empty()) {
            disable_nat(safe_iface, safe_share);
        }
    }
    
    // Cleanup config files
    std::filesystem::remove(HOSTAPD_CONF);
    std::filesystem::remove(DNSMASQ_CONF);
    
    // === Restore interface to NetworkManager ===
    if (!safe_iface.empty()) {
        // Bring down and reset
        SEC.exec("ip link set " + safe_iface + " down", false);
        SEC.exec("ip addr flush dev " + safe_iface, false);
        
        // Return to managed mode
        SEC.exec("iw dev " + safe_iface + " set type managed", false);
        
        // Give back to NetworkManager
        SEC.exec("nmcli device set " + safe_iface + " managed yes", false);
        
        // Restart wpa_supplicant
        SEC.exec("systemctl restart wpa_supplicant", false);
        
        // Bring interface back up
        SEC.exec("ip link set " + safe_iface + " up", false);
    }
    
    clear_state();
    return true;
}

bool is_running() {
    std::lock_guard<std::mutex> lock(s_state_mutex);
    
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
    
    std::string safe_iface = SEC.safe_interface(s_current_config.interface);
    if (safe_iface.empty()) return result;
    log("get_clients: interface = " + safe_iface);
    
    // Try hostapd_cli first (comes with hostapd), then iw as fallback
    auto station_dump = SEC.exec_timeout("hostapd_cli -i " + safe_iface + " all_sta", 2, false).out;
    
    // If hostapd_cli fails, try iw
    if (station_dump.empty() ||
        station_dump.find("not found") != std::string::npos || 
        station_dump.find("Failed to connect") != std::string::npos ||
        station_dump.find("No such file") != std::string::npos ||
        station_dump.find("timed out") != std::string::npos) {
        log("hostapd_cli failed, trying iw");
        station_dump = SEC.exec_timeout("iw dev " + safe_iface + " station dump", 2, false).out;
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
    SEC.exec("sysctl -w net.ipv4.ip_forward=1", false).out;
    
    // Remove existing rules first to prevent duplicates
    disable_nat(ap_iface, wan_iface);
    
    // Setup NAT
    SEC.exec("iptables -t nat -A POSTROUTING -o " + wan_iface + " -j MASQUERADE", false).out;
    SEC.exec("iptables -A FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT", false).out;
    SEC.exec("iptables -A FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT", false).out;
    
    return true;
}

bool disable_nat(const std::string& ap_iface, const std::string& wan_iface) {
    SEC.exec("iptables -t nat -D POSTROUTING -o " + wan_iface + " -j MASQUERADE", false).out;
    SEC.exec("iptables -D FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT", false).out;
    SEC.exec("iptables -D FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT", false).out;
    
    return true;
}

std::vector<ChannelInfo> scan_channels(const std::string& iface) {
    std::vector<ChannelInfo> result;
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) return result;
    log("Scanning channels on " + safe_iface);
    
    // Use iwlist or iw to scan
    auto scan_output = SEC.exec_timeout("iwlist " + safe_iface + " scan", 10, false).out;
    
    if (scan_output.empty() || scan_output.find("not found") != std::string::npos) {
        // Try iw instead
        scan_output = SEC.exec_timeout("iw dev " + safe_iface + " scan", 10, false).out;
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
