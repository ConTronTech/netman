#include "hotspot.hpp"
#include "../helpers/exec.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <signal.h>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace hotspot {

static Config s_current_config;
static bool s_running = false;
static std::string s_last_error;

// Debug log
static std::ofstream s_log;
static void log(const std::string& msg) {
    if (!s_log.is_open()) {
        s_log.open("/tmp/netman_hotspot.log", std::ios::app);
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
    
    if (exec::run("which hostapd 2>/dev/null").empty()) {
        missing.push_back("hostapd");
    }
    if (exec::run("which dnsmasq 2>/dev/null").empty()) {
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

std::vector<std::string> get_ap_capable_interfaces() {
    std::vector<std::string> result;
    std::vector<std::string> wifi_ifaces;
    
    // Method 1: Check /sys/class/net/*/wireless (most reliable)
    auto sys_output = exec::run("ls -d /sys/class/net/*/wireless 2>/dev/null | cut -d'/' -f5");
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
        auto iw_output = exec::run("iw dev 2>/dev/null | grep Interface | awk '{print $2}'");
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
        auto iwc_output = exec::run("iwconfig 2>/dev/null | grep -v 'no wireless' | grep -E '^[a-z]' | awk '{print $1}'");
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
        // Get phy number
        auto phy = exec::run("iw dev " + wif + " info 2>/dev/null | grep wiphy | awk '{print $2}'");
        phy = trim(phy);
        
        if (phy.empty()) {
            // Can't verify AP mode, but include it anyway with warning
            result.push_back(wif);
            continue;
        }
        
        // Check for AP mode support
        auto modes = exec::run("iw phy phy" + phy + " info 2>/dev/null | grep -E '^\\s+\\* AP$'");
        if (!modes.empty()) {
            result.push_back(wif);
        } else {
            // Broader check
            modes = exec::run("iw phy phy" + phy + " info 2>/dev/null | grep -i 'AP'");
            if (modes.find("* AP") != std::string::npos) {
                result.push_back(wif);
            } else {
                // Include anyway, let hostapd fail if it doesn't work
                result.push_back(wif);
            }
        }
    }
    
    return result;
}

bool supports_5ghz(const std::string& iface) {
    // Method 1: Check via iw phy
    auto phy = exec::run("iw dev " + iface + " info 2>/dev/null | grep wiphy | awk '{print $2}'");
    phy = trim(phy);
    
    if (!phy.empty()) {
        // Check for 5GHz frequencies (5000-5999 MHz)
        auto freqs = exec::run("iw phy phy" + phy + " info 2>/dev/null | grep -E '5[0-9]{3}'");
        if (!freqs.empty()) return true;
        
        // Check for "Band 2" which is typically 5GHz
        auto band = exec::run("iw phy phy" + phy + " info 2>/dev/null | grep -i 'Band 2'");
        if (!band.empty()) return true;
    }
    
    // Method 2: Check via iw list
    auto iw_list = exec::run("iw list 2>/dev/null | grep -A 50 'Wiphy' | grep -E '5[0-9]{3}'");
    if (!iw_list.empty()) return true;
    
    // Method 3: Assume true if we can't determine (let hostapd fail gracefully)
    // Most modern cards support both bands
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
    if (cfg.password.length() < 8 && !cfg.password.empty()) {
        s_last_error = "Password must be 8+ chars";
        log("ERROR: " + s_last_error);
        return false;
    }
    
    // === CRITICAL: Release interface from other managers ===
    log("Releasing interface from NetworkManager...");
    
    // Stop NetworkManager from managing this interface
    auto nm_result = exec::run("nmcli device set " + cfg.interface + " managed no 2>&1");
    log("nmcli result: " + nm_result);
    
    // Kill any wpa_supplicant on this interface
    exec::run("pkill -f 'wpa_supplicant.*" + cfg.interface + "' 2>/dev/null");
    exec::run("killall wpa_supplicant 2>/dev/null");
    
    // Small delay for processes to die
    exec::run("sleep 0.5");
    
    // Bring down interface
    log("Bringing down interface...");
    exec::run("ip link set " + cfg.interface + " down");
    exec::run("ip addr flush dev " + cfg.interface);
    
    // Set interface type
    exec::run("iw dev " + cfg.interface + " set type managed 2>/dev/null");
    
    // Set static IP for AP
    log("Setting IP 192.168.50.1...");
    auto ip_result = exec::run("ip addr add 192.168.50.1/24 dev " + cfg.interface + " 2>&1");
    log("ip addr result: " + ip_result);
    
    exec::run("ip link set " + cfg.interface + " up");
    
    // Verify interface is up
    auto link_state = exec::run("ip link show " + cfg.interface + " 2>&1");
    log("Link state: " + link_state);
    
    // Set regulatory domain (required for 5GHz AP mode)
    log("Setting regulatory domain to " + cfg.country_code);
    exec::run("iw reg set " + cfg.country_code + " 2>&1");
    exec::run("sleep 0.3");
    
    // Generate hostapd config
    log("Writing hostapd config to " + HOSTAPD_CONF);
    std::ofstream hconf(HOSTAPD_CONF);
    hconf << "interface=" << cfg.interface << "\n";
    hconf << "driver=nl80211\n";
    hconf << "ssid=" << cfg.ssid << "\n";
    hconf << "country_code=" << cfg.country_code << "\n";
    hconf << "ieee80211d=1\n";  // Advertise country code
    hconf << "hw_mode=" << (cfg.band == "5" ? "a" : "g") << "\n";
    hconf << "channel=" << cfg.channel << "\n";
    hconf << "ieee80211n=1\n";
    if (cfg.band == "5") {
        hconf << "ieee80211ac=1\n";
    }
    hconf << "wmm_enabled=1\n";
    hconf << "ignore_broadcast_ssid=" << (cfg.hidden ? "1" : "0") << "\n";
    
    if (!cfg.password.empty()) {
        hconf << "auth_algs=1\n";
        hconf << "wpa=2\n";
        hconf << "wpa_key_mgmt=WPA-PSK\n";
        hconf << "wpa_pairwise=CCMP\n";
        hconf << "rsn_pairwise=CCMP\n";
        hconf << "wpa_passphrase=" << cfg.password << "\n";
    }
    hconf.close();
    
    // Log config contents
    auto conf_contents = exec::run("cat " + HOSTAPD_CONF);
    log("hostapd.conf:\n" + conf_contents);
    
    // Generate dnsmasq config
    log("Writing dnsmasq config to " + DNSMASQ_CONF);
    std::ofstream dconf(DNSMASQ_CONF);
    dconf << "interface=" << cfg.interface << "\n";
    dconf << "bind-interfaces\n";
    dconf << "dhcp-range=192.168.50.10,192.168.50.254,24h\n";
    dconf << "dhcp-option=option:router,192.168.50.1\n";
    dconf << "dhcp-option=option:dns-server,8.8.8.8,8.8.4.4\n";
    dconf << "dhcp-leasefile=" << DNSMASQ_LEASES << "\n";
    dconf.close();
    
    // Start hostapd (foreground briefly to capture output)
    log("Starting hostapd...");
    auto hostapd_cmd = "hostapd -B -P " + HOSTAPD_PID + " " + HOSTAPD_CONF + " 2>&1";
    log("Command: " + hostapd_cmd);
    auto hostapd_result = exec::run(hostapd_cmd);
    log("hostapd output: " + hostapd_result);
    
    // Wait for it to start
    exec::run("sleep 1");
    
    // Check if hostapd started
    if (!std::filesystem::exists(HOSTAPD_PID)) {
        // Try to get more info
        auto ps = exec::run("ps aux | grep hostapd");
        log("hostapd processes: " + ps);
        
        s_last_error = "hostapd failed to start: " + hostapd_result;
        log("ERROR: " + s_last_error);
        return false;
    }
    
    auto hostapd_pid = exec::run("cat " + HOSTAPD_PID);
    log("hostapd started with PID: " + hostapd_pid);
    
    // Start dnsmasq
    log("Starting dnsmasq...");
    auto dnsmasq_result = exec::run("dnsmasq -C " + DNSMASQ_CONF + " --pid-file=" + DNSMASQ_PID + " 2>&1");
    log("dnsmasq output: " + dnsmasq_result);
    
    // Enable NAT if sharing internet
    if (!cfg.share_from.empty()) {
        log("Enabling NAT from " + cfg.share_from);
        enable_nat(cfg.interface, cfg.share_from);
    }
    
    s_current_config = cfg;
    s_running = true;
    log("=== Hotspot started successfully ===");
    return true;
}

bool stop() {
    std::string iface = s_current_config.interface;
    
    // Kill hostapd
    if (std::filesystem::exists(HOSTAPD_PID)) {
        std::ifstream pf(HOSTAPD_PID);
        std::string pid;
        std::getline(pf, pid);
        if (!pid.empty()) {
            kill(std::stoi(pid), SIGTERM);
        }
        std::filesystem::remove(HOSTAPD_PID);
    }
    
    // Also kill by name in case PID file is stale
    exec::run("pkill -f 'hostapd.*netman' 2>/dev/null");
    
    // Kill dnsmasq
    if (std::filesystem::exists(DNSMASQ_PID)) {
        std::ifstream pf(DNSMASQ_PID);
        std::string pid;
        std::getline(pf, pid);
        if (!pid.empty()) {
            kill(std::stoi(pid), SIGTERM);
        }
        std::filesystem::remove(DNSMASQ_PID);
    }
    
    exec::run("pkill -f 'dnsmasq.*netman' 2>/dev/null");
    
    // Disable NAT
    if (!s_current_config.share_from.empty()) {
        disable_nat(s_current_config.interface, s_current_config.share_from);
    }
    
    // Cleanup config files
    std::filesystem::remove(HOSTAPD_CONF);
    std::filesystem::remove(DNSMASQ_CONF);
    
    // === Restore interface to NetworkManager ===
    if (!iface.empty()) {
        // Bring down and reset
        exec::run("ip link set " + iface + " down 2>/dev/null");
        exec::run("ip addr flush dev " + iface + " 2>/dev/null");
        
        // Return to managed mode
        exec::run("iw dev " + iface + " set type managed 2>/dev/null");
        
        // Give back to NetworkManager
        exec::run("nmcli device set " + iface + " managed yes 2>/dev/null");
        
        // Restart wpa_supplicant for this interface
        exec::run("systemctl restart wpa_supplicant 2>/dev/null");
        
        // Bring interface back up
        exec::run("ip link set " + iface + " up 2>/dev/null");
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
    std::string pid;
    std::getline(pf, pid);
    
    if (pid.empty()) {
        s_running = false;
        return false;
    }
    
    // Check if process exists
    if (kill(std::stoi(pid), 0) != 0) {
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
    
    // Get currently connected stations from iw
    std::string iface = s_current_config.interface;
    log("get_clients: interface = " + iface);
    
    auto station_dump = exec::run("iw dev " + iface + " station dump 2>&1");
    log("station dump output:\n" + station_dump);
    
    // Parse station dump
    std::istringstream ss(station_dump);
    std::string line;
    Client current;
    bool in_station = false;
    
    while (std::getline(ss, line)) {
        if (line.find("Station ") == 0) {
            // New station entry
            if (in_station && !current.mac.empty()) {
                current.connected = true;
                result.push_back(current);
            }
            current = Client{};
            in_station = true;
            
            // Extract MAC: "Station aa:bb:cc:dd:ee:ff (on wlan0)"
            size_t start = 8;  // After "Station "
            size_t end = line.find(" ", start);
            if (end != std::string::npos) {
                current.mac = line.substr(start, end - start);
            }
        } else if (in_station) {
            // Parse station info
            if (line.find("signal:") != std::string::npos) {
                // "signal: -45 dBm"
                size_t pos = line.find(":");
                if (pos != std::string::npos) {
                    std::string val = line.substr(pos + 1);
                    current.signal = std::stoi(val);
                    current.signal_percent = dbm_to_percent(current.signal);
                }
            } else if (line.find("rx bytes:") != std::string::npos) {
                size_t pos = line.find(":");
                if (pos != std::string::npos) {
                    current.rx_bytes = std::stoull(line.substr(pos + 1));
                }
            } else if (line.find("tx bytes:") != std::string::npos) {
                size_t pos = line.find(":");
                if (pos != std::string::npos) {
                    current.tx_bytes = std::stoull(line.substr(pos + 1));
                }
            }
        }
    }
    
    // Don't forget last station
    if (in_station && !current.mac.empty()) {
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
            
            // Convert MAC to lowercase for comparison
            std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
            
            for (auto& client : result) {
                std::string client_mac = client.mac;
                std::transform(client_mac.begin(), client_mac.end(), client_mac.begin(), ::tolower);
                
                if (client_mac == mac) {
                    client.ip = ip;
                    client.hostname = (hostname == "*") ? "" : hostname;
                    break;
                }
            }
        }
    }
    
    return result;
}

bool enable_nat(const std::string& ap_iface, const std::string& wan_iface) {
    // Enable IP forwarding
    exec::run("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    // Setup NAT
    exec::run("iptables -t nat -A POSTROUTING -o " + wan_iface + " -j MASQUERADE");
    exec::run("iptables -A FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT");
    exec::run("iptables -A FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT");
    
    return true;
}

bool disable_nat(const std::string& ap_iface, const std::string& wan_iface) {
    exec::run("iptables -t nat -D POSTROUTING -o " + wan_iface + " -j MASQUERADE 2>/dev/null");
    exec::run("iptables -D FORWARD -i " + ap_iface + " -o " + wan_iface + " -j ACCEPT 2>/dev/null");
    exec::run("iptables -D FORWARD -i " + wan_iface + " -o " + ap_iface + " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");
    
    return true;
}

} // namespace hotspot
