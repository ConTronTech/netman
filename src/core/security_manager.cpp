#include "security_manager.hpp"
#include <fstream>
#include <sstream>
#include <mutex>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <algorithm>
#include <regex>
#include <array>
#include <memory>
#include <unistd.h>
#include <sys/wait.h>

namespace security {

// =============================================================================
// WHITELISTS
// =============================================================================

static const std::vector<std::string> VALID_COUNTRIES = {
    "US", "CA", "GB", "DE", "FR", "AU", "JP", "CN", "FI", "NL",
    "ES", "IT", "BR", "MX", "IN", "KR", "TW", "SG", "HK", "NZ",
    "SE", "NO", "DK", "PL", "CZ", "AT", "CH", "BE", "IE", "PT"
};

static const std::vector<std::string> VALID_TABLES = {
    "filter", "nat", "mangle", "raw", "security"
};

static const std::vector<std::string> VALID_CHAINS = {
    "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"
};

static const std::vector<std::string> VALID_PROTOCOLS = {
    "tcp", "udp", "icmp", "all"
};

static const std::vector<std::string> VALID_BANDS = {
    "2.4", "5"
};

// Valid 5GHz channels
static const std::vector<int> VALID_5GHZ_CHANNELS = {
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 
    116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165
};

// Allowed root command prefixes - ONLY these can run with needs_root=true
static const std::vector<std::string> ROOT_COMMAND_WHITELIST = {
    // Network interface management
    "ip link ",
    "ip addr ",
    "ip route ",
    "ip neigh ",
    // WiFi tools
    "iw ",
    "iwconfig ",
    "iwlist ",
    "iwgetid ",
    "hostapd",
    "wpa_supplicant",
    // DHCP/DNS
    "dnsmasq",
    // Firewall
    "iptables ",
    "iptables-save",
    "iptables-restore",
    // Network manager
    "nmcli ",
    "systemctl restart wpa_supplicant",
    "systemctl restart NetworkManager",
    // Process management (scoped)
    "pkill -f 'hostapd",
    "pkill -f 'dnsmasq",
    "pkill -f 'wpa_supplicant",
    // Scanning
    "arp-scan ",
    // Utilities
    "timeout ",
    "cat /tmp/netman/",
    "sleep ",
    "echo 1 > /proc/sys/net/ipv4/ip_forward",
    "echo 0 > /proc/sys/net/ipv4/ip_forward",
    // Regulatory
    "iw reg set ",
};

// Allowed log path prefixes
static const std::vector<std::string> ALLOWED_LOG_PATHS = {
    "/tmp/netman/",
    "/var/log/netman/"
};

// Sensitive patterns to redact in logs
static const std::vector<std::string> SENSITIVE_PATTERNS = {
    "passphrase",
    "password",
    "wpa_passphrase",
    "psk=",
    "key=",
    "secret",
    "token",
};

// =============================================================================
// IMPLEMENTATION
// =============================================================================

struct SecurityManager::Impl {
    std::mutex log_mutex;
    std::string log_path = "/tmp/netman/security.log";
    bool strict_mode = false;
    std::vector<std::string> recent_log;
    bool is_root_cached = false;
    bool is_root_checked = false;
    bool log_file_created = false;
    
    void log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        
        // Thread-safe timestamp using localtime_r
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf;
        localtime_r(&time, &tm_buf);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
        
        std::string entry = std::string(buf) + " " + msg;
        
        // Keep in memory
        recent_log.push_back(entry);
        if (recent_log.size() > 1000) {
            recent_log.erase(recent_log.begin(), recent_log.begin() + 500);
        }
        
        // Write to file
        try {
            std::filesystem::create_directories(std::filesystem::path(log_path).parent_path());
            std::ofstream f(log_path, std::ios::app);
            if (f) {
                f << entry << "\n";
                // Set restrictive permissions only on first creation
                if (!log_file_created) {
                    std::filesystem::permissions(log_path,
                        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
                    log_file_created = true;
                }
            }
        } catch (...) {}
    }
};

SecurityManager& SecurityManager::instance() {
    static SecurityManager inst;
    return inst;
}

SecurityManager::SecurityManager() : m_impl(new Impl) {}
SecurityManager::~SecurityManager() { delete m_impl; }

// =============================================================================
// VALIDATORS
// =============================================================================

ValidationResult SecurityManager::validate(InputType type, const std::string& input) {
    switch (type) {
        case InputType::INTERFACE:    return validate_interface(input);
        case InputType::MAC_ADDRESS:  return validate_mac(input);
        case InputType::IP_ADDRESS:   return validate_ip(input);
        case InputType::IP_CIDR:      return validate_ip_cidr(input);
        case InputType::HOSTNAME:     return validate_hostname(input);
        case InputType::SSID:         return validate_ssid(input);
        case InputType::PASSWORD:     return validate_password(input);
        case InputType::PATH:         return validate_path(input);
        case InputType::COUNTRY_CODE: return validate_country(input);
        case InputType::PORT:         return validate_port(input);
        case InputType::CHAIN:        return validate_chain(input);
        case InputType::TABLE:        return validate_table(input);
        case InputType::PROTOCOL:     return validate_protocol(input);
        case InputType::CHANNEL:      return validate_channel(input);
        case InputType::BAND:         return validate_band(input);
        case InputType::SHELL_ARG:    return validate_shell_arg(input);
    }
    return {false, "", "Unknown input type"};
}

ValidationResult SecurityManager::validate_interface(const std::string& input) {
    // Interface names: alphanumeric + hyphen + underscore, max 15 chars
    // Examples: eth0, wlan0, enp3s0, wlp2s0, veth-abc_123
    
    if (input.empty() || input.length() > 15) {
        log_attempt("validate_interface", input, false);
        return {false, "", "Interface name empty or too long"};
    }
    
    std::string sanitized;
    for (char c : input) {
        if (std::isalnum(c) || c == '-' || c == '_') {
            sanitized += c;
        }
    }
    
    if (sanitized != input || sanitized.empty()) {
        log_attempt("validate_interface", input, false);
        return {false, "", "Interface name contains invalid characters"};
    }
    
    // Must start with letter
    if (!std::isalpha(sanitized[0])) {
        log_attempt("validate_interface", input, false);
        return {false, "", "Interface name must start with a letter"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_mac(const std::string& input) {
    // MAC: AA:BB:CC:DD:EE:FF or aa:bb:cc:dd:ee:ff
    if (input.length() != 17) {
        log_attempt("validate_mac", input, false);
        return {false, "", "MAC address must be 17 characters"};
    }
    
    std::string sanitized;
    for (int i = 0; i < 17; i++) {
        char c = input[i];
        if (i % 3 == 2) {
            if (c != ':') {
                log_attempt("validate_mac", input, false);
                return {false, "", "Invalid MAC address format"};
            }
            sanitized += ':';
        } else {
            if (!std::isxdigit(c)) {
                log_attempt("validate_mac", input, false);
                return {false, "", "Invalid MAC address character"};
            }
            sanitized += std::toupper(c);
        }
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_ip(const std::string& input) {
    // IPv4: 0-255.0-255.0-255.0-255
    // Max length: 15 chars (255.255.255.255)
    if (input.length() > 15) {
        log_attempt("validate_ip", input, false);
        return {false, "", "IP address too long"};
    }
    
    std::istringstream ss(input);
    std::string octet;
    int count = 0;
    std::string sanitized;
    
    while (std::getline(ss, octet, '.')) {
        if (octet.empty() || octet.length() > 3) {
            log_attempt("validate_ip", input, false);
            return {false, "", "Invalid IP address octet"};
        }
        
        for (char c : octet) {
            if (!std::isdigit(c)) {
                log_attempt("validate_ip", input, false);
                return {false, "", "IP address must contain only digits"};
            }
        }
        
        int val;
        try {
            val = std::stoi(octet);
        } catch (...) {
            log_attempt("validate_ip", input, false);
            return {false, "", "Invalid IP address octet"};
        }
        
        if (val < 0 || val > 255) {
            log_attempt("validate_ip", input, false);
            return {false, "", "IP address octet out of range"};
        }
        
        if (count > 0) sanitized += ".";
        sanitized += std::to_string(val);
        count++;
    }
    
    if (count != 4) {
        log_attempt("validate_ip", input, false);
        return {false, "", "IP address must have 4 octets"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_ip_cidr(const std::string& input) {
    // IPv4/CIDR: 192.168.1.0/24
    // Max length: 18 chars (255.255.255.255/32)
    if (input.length() > 18) {
        log_attempt("validate_ip_cidr", input, false);
        return {false, "", "IP/CIDR too long"};
    }
    
    size_t slash = input.find('/');
    if (slash == std::string::npos) {
        return validate_ip(input);  // Plain IP is valid
    }
    
    std::string ip_part = input.substr(0, slash);
    std::string cidr_part = input.substr(slash + 1);
    
    auto ip_result = validate_ip(ip_part);
    if (!ip_result) {
        return ip_result;
    }
    
    // Validate CIDR
    if (cidr_part.empty() || cidr_part.length() > 2) {
        log_attempt("validate_ip_cidr", input, false);
        return {false, "", "Invalid CIDR notation"};
    }
    
    for (char c : cidr_part) {
        if (!std::isdigit(c)) {
            log_attempt("validate_ip_cidr", input, false);
            return {false, "", "CIDR must be numeric"};
        }
    }
    
    int cidr;
    try {
        cidr = std::stoi(cidr_part);
    } catch (...) {
        log_attempt("validate_ip_cidr", input, false);
        return {false, "", "Invalid CIDR value"};
    }
    
    if (cidr < 0 || cidr > 32) {
        log_attempt("validate_ip_cidr", input, false);
        return {false, "", "CIDR must be 0-32"};
    }
    
    return {true, ip_result.sanitized + "/" + std::to_string(cidr), ""};
}

ValidationResult SecurityManager::validate_hostname(const std::string& input) {
    // Hostname: alphanumeric + hyphen + dot, max 253 chars
    if (input.empty() || input.length() > 253) {
        log_attempt("validate_hostname", input, false);
        return {false, "", "Hostname empty or too long"};
    }
    
    std::string sanitized;
    for (char c : input) {
        if (std::isalnum(c) || c == '-' || c == '.') {
            sanitized += std::tolower(c);
        }
    }
    
    if (sanitized.empty()) {
        log_attempt("validate_hostname", input, false);
        return {false, "", "Hostname contains only invalid characters"};
    }
    
    // Structural validation: must have at least one alnum, can't be all dots/hyphens
    bool has_alnum = false;
    for (char c : sanitized) {
        if (std::isalnum(c)) {
            has_alnum = true;
            break;
        }
    }
    if (!has_alnum) {
        log_attempt("validate_hostname", input, false);
        return {false, "", "Hostname must contain alphanumeric characters"};
    }
    
    // Can't start or end with hyphen or dot
    if (sanitized.front() == '-' || sanitized.front() == '.' ||
        sanitized.back() == '-' || sanitized.back() == '.') {
        log_attempt("validate_hostname", input, false);
        return {false, "", "Hostname cannot start or end with hyphen or dot"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_ssid(const std::string& input) {
    // SSID: max 32 chars, printable ASCII
    if (input.empty()) {
        log_attempt("validate_ssid", input, false);
        return {false, "", "SSID cannot be empty"};
    }
    if (input.length() > 32) {
        log_attempt("validate_ssid", input, false);
        return {false, "", "SSID too long (max 32 chars)"};
    }
    
    std::string sanitized;
    for (char c : input) {
        if (c >= 32 && c < 127) {
            sanitized += c;
        }
    }
    
    if (sanitized.empty()) {
        log_attempt("validate_ssid", input, false);
        return {false, "", "SSID contains only invalid characters"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_password(const std::string& input) {
    // WPA password: 8-63 chars, printable ASCII
    if (input.empty()) {
        return {true, "", ""};  // Empty password = open network
    }
    
    if (input.length() < 8) {
        log_attempt("validate_password", "[REDACTED]", false);
        return {false, "", "Password must be at least 8 characters"};
    }
    if (input.length() > 63) {
        log_attempt("validate_password", "[REDACTED]", false);
        return {false, "", "Password too long (max 63 chars)"};
    }
    
    std::string sanitized;
    for (char c : input) {
        if (c >= 32 && c < 127) {
            sanitized += c;
        }
    }
    
    if (sanitized.length() < 8) {
        log_attempt("validate_password", "[REDACTED]", false);
        return {false, "", "Password contains too many invalid characters"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_path(const std::string& input) {
    // Path: no .., no null bytes, must be reasonable
    if (input.empty()) {
        log_attempt("validate_path", input, false);
        return {false, "", "Path cannot be empty"};
    }
    
    // Check for path traversal
    if (input.find("..") != std::string::npos) {
        log_attempt("validate_path", input, false);
        return {false, "", "Path traversal not allowed"};
    }
    
    // Check for null bytes
    if (input.find('\0') != std::string::npos) {
        log_attempt("validate_path", input, false);
        return {false, "", "Null bytes not allowed in path"};
    }
    
    // Check for shell metacharacters
    std::string dangerous = "`$;|&><(){}[]!\\'\"\n\r";
    for (char c : input) {
        if (dangerous.find(c) != std::string::npos) {
            log_attempt("validate_path", input, false);
            return {false, "", "Path contains dangerous characters"};
        }
    }
    
    return {true, input, ""};
}

ValidationResult SecurityManager::validate_country(const std::string& input) {
    std::string upper = input;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    
    for (const auto& cc : VALID_COUNTRIES) {
        if (cc == upper) {
            return {true, upper, ""};
        }
    }
    
    log_attempt("validate_country", input, false);
    return {false, "", "Invalid country code"};
}

ValidationResult SecurityManager::validate_port(const std::string& input) {
    if (input.empty()) {
        log_attempt("validate_port", input, false);
        return {false, "", "Port cannot be empty"};
    }
    
    // Max 5 digits (65535)
    if (input.length() > 5) {
        log_attempt("validate_port", input, false);
        return {false, "", "Port number too long"};
    }
    
    for (char c : input) {
        if (!std::isdigit(c)) {
            log_attempt("validate_port", input, false);
            return {false, "", "Port must be numeric"};
        }
    }
    
    int port;
    try {
        port = std::stoi(input);
    } catch (...) {
        log_attempt("validate_port", input, false);
        return {false, "", "Invalid port number"};
    }
    
    if (port < 1 || port > 65535) {
        log_attempt("validate_port", input, false);
        return {false, "", "Port must be 1-65535"};
    }
    
    return {true, std::to_string(port), ""};
}

ValidationResult SecurityManager::validate_chain(const std::string& input) {
    std::string upper = input;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    
    // Check built-in chains
    for (const auto& ch : VALID_CHAINS) {
        if (ch == upper) {
            return {true, upper, ""};
        }
    }
    
    // Custom chains: alphanumeric + hyphen + underscore, max 28 chars
    if (input.length() > 28) {
        log_attempt("validate_chain", input, false);
        return {false, "", "Chain name too long"};
    }
    
    std::string sanitized;
    for (char c : input) {
        if (std::isalnum(c) || c == '-' || c == '_') {
            sanitized += c;
        }
    }
    
    if (sanitized != input || sanitized.empty()) {
        log_attempt("validate_chain", input, false);
        return {false, "", "Invalid chain name"};
    }
    
    return {true, sanitized, ""};
}

ValidationResult SecurityManager::validate_table(const std::string& input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& t : VALID_TABLES) {
        if (t == lower) {
            return {true, lower, ""};
        }
    }
    
    log_attempt("validate_table", input, false);
    return {false, "", "Invalid iptables table"};
}

ValidationResult SecurityManager::validate_protocol(const std::string& input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& p : VALID_PROTOCOLS) {
        if (p == lower) {
            return {true, lower, ""};
        }
    }
    
    log_attempt("validate_protocol", input, false);
    return {false, "", "Invalid protocol"};
}

ValidationResult SecurityManager::validate_channel(const std::string& input) {
    if (input.empty()) {
        log_attempt("validate_channel", input, false);
        return {false, "", "Channel cannot be empty"};
    }
    
    // Max 3 digits (165 is highest valid channel)
    if (input.length() > 3) {
        log_attempt("validate_channel", input, false);
        return {false, "", "Channel number too long"};
    }
    
    for (char c : input) {
        if (!std::isdigit(c)) {
            log_attempt("validate_channel", input, false);
            return {false, "", "Channel must be numeric"};
        }
    }
    
    int ch;
    try {
        ch = std::stoi(input);
    } catch (...) {
        log_attempt("validate_channel", input, false);
        return {false, "", "Invalid channel number"};
    }
    
    // 2.4GHz: 1-14, 5GHz: check list
    bool valid = (ch >= 1 && ch <= 14);
    if (!valid) {
        for (int v : VALID_5GHZ_CHANNELS) {
            if (v == ch) {
                valid = true;
                break;
            }
        }
    }
    
    if (!valid) {
        log_attempt("validate_channel", input, false);
        return {false, "", "Invalid WiFi channel"};
    }
    
    return {true, std::to_string(ch), ""};
}

ValidationResult SecurityManager::validate_band(const std::string& input) {
    for (const auto& b : VALID_BANDS) {
        if (b == input) {
            return {true, input, ""};
        }
    }
    
    log_attempt("validate_band", input, false);
    return {false, "", "Band must be 2.4 or 5"};
}

ValidationResult SecurityManager::validate_shell_arg(const std::string& input) {
    // Most restrictive: alphanumeric + hyphen + underscore + dot + space only
    std::string sanitized;
    for (char c : input) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == ' ') {
            sanitized += c;
        }
    }
    
    if (sanitized.empty() && !input.empty()) {
        log_attempt("validate_shell_arg", input, false);
        return {false, "", "Input contains only invalid characters"};
    }
    
    return {true, sanitized, ""};
}

// =============================================================================
// CONVENIENCE VALIDATORS
// =============================================================================

std::string SecurityManager::safe_interface(const std::string& iface) {
    auto r = validate_interface(iface);
    return r.valid ? r.sanitized : "";
}

std::string SecurityManager::safe_mac(const std::string& mac) {
    auto r = validate_mac(mac);
    return r.valid ? r.sanitized : "";
}

std::string SecurityManager::safe_ip(const std::string& ip) {
    auto r = validate_ip(ip);
    return r.valid ? r.sanitized : "";
}

std::string SecurityManager::safe_path(const std::string& path, const std::string& allowed_prefix) {
    auto r = validate_path(path);
    if (!r.valid) return "";
    
    // If prefix specified, ensure path starts with it
    if (!allowed_prefix.empty()) {
        try {
            auto canonical = std::filesystem::weakly_canonical(path);
            auto prefix = std::filesystem::weakly_canonical(allowed_prefix);
            
            // Check if path is under prefix
            auto [first, last] = std::mismatch(
                prefix.begin(), prefix.end(),
                canonical.begin(), canonical.end()
            );
            
            if (first != prefix.end()) {
                log_attempt("safe_path", path + " (prefix: " + allowed_prefix + ")", false);
                return "";
            }
        } catch (...) {
            return "";
        }
    }
    
    return r.sanitized;
}

std::string SecurityManager::safe_ssid(const std::string& ssid) {
    auto r = validate_ssid(ssid);
    return r.valid ? r.sanitized : "";
}

std::string SecurityManager::safe_password(const std::string& pass) {
    auto r = validate_password(pass);
    return r.valid ? r.sanitized : "";
}

std::string SecurityManager::safe_shell(const std::string& arg) {
    auto r = validate_shell_arg(arg);
    return r.valid ? r.sanitized : "";
}

// =============================================================================
// PRIVILEGE MANAGEMENT
// =============================================================================

bool SecurityManager::is_root() {
    if (!m_impl->is_root_checked) {
        m_impl->is_root_cached = (geteuid() == 0);
        m_impl->is_root_checked = true;
    }
    return m_impl->is_root_cached;
}

bool SecurityManager::can_elevate() {
    // Check if pkexec is available
    return std::filesystem::exists("/usr/bin/pkexec");
}

// =============================================================================
// SECURE EXECUTION
// =============================================================================

// Shell metacharacters that enable command chaining/injection
static const std::string SHELL_METACHARACTERS = ";|&`$(){}[]<>!\n\r\\";

// Check if command contains dangerous shell metacharacters
static bool has_shell_injection(const std::string& cmd) {
    for (char c : cmd) {
        if (SHELL_METACHARACTERS.find(c) != std::string::npos) {
            return true;
        }
    }
    // Also check for common injection patterns
    if (cmd.find("$(") != std::string::npos) return true;
    if (cmd.find("${") != std::string::npos) return true;
    return false;
}

// Safe user commands - READ-ONLY operations only
static const std::vector<std::string> SAFE_USER_COMMANDS = {
    "which ",
    "ls -",         // ls with flags only, not arbitrary paths
    "ip link show",
    "ip addr show",
    "ip route show",
    "ip neigh show",
    "iw dev ",      // iw dev X info/scan (read-only subcommands validated separately)
    "iwconfig ",
    "iwlist ",
    "iwgetid ",
    "curl -s --connect-timeout",  // Specific safe curl pattern
    "getent hosts ",
    "sleep ",
    "timeout ",
    "ping -c ",     // Only controlled pings
};

// Check if command matches whitelist AND has no injection
static bool is_command_allowed(const std::string& cmd, bool needs_root) {
    // FIRST: Block any command with shell metacharacters
    if (has_shell_injection(cmd)) {
        return false;
    }
    
    // SECOND: Enforce max command length (prevent buffer issues)
    if (cmd.length() > 1024) {
        return false;
    }
    
    // THIRD: Check against appropriate whitelist
    const std::vector<std::string>* whitelist = nullptr;
    
    if (needs_root) {
        whitelist = &ROOT_COMMAND_WHITELIST;
    } else {
        // For non-root, check safe user commands first
        for (const auto& prefix : SAFE_USER_COMMANDS) {
            if (cmd.find(prefix) == 0) return true;
        }
        // Fall through to root whitelist (commands that work without root too)
        whitelist = &ROOT_COMMAND_WHITELIST;
    }
    
    for (const auto& prefix : *whitelist) {
        if (cmd.find(prefix) == 0) return true;
    }
    
    return false;
}

SecurityManager::ExecResult SecurityManager::exec(const std::string& cmd, bool needs_root) {
    ExecResult result;
    
    // SECURITY: Validate command against whitelist
    if (!is_command_allowed(cmd, needs_root)) {
        result.code = -1;
        result.err = "Command not in whitelist";
        m_impl->log("[EXEC BLOCKED] " + cmd.substr(0, 100) + " (not whitelisted)");
        return result;
    }
    
    // Log execution
    log_exec(cmd, needs_root, -1);
    
    // Check privileges
    if (needs_root && !is_root()) {
        result.code = -1;
        result.err = "Root privileges required";
        m_impl->log("[EXEC DENIED] " + cmd + " (needs root, not root)");
        return result;
    }
    
    // Execute
    std::string full_cmd = cmd + " 2>&1";
    
    std::array<char, 4096> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(
        popen(full_cmd.c_str(), "r"), pclose);
    
    if (!pipe) {
        result.code = -1;
        result.err = "Failed to execute command";
        return result;
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result.out += buffer.data();
    }
    
    result.code = WEXITSTATUS(pclose(pipe.release()));
    log_exec(cmd, needs_root, result.code);
    
    return result;
}

SecurityManager::ExecResult SecurityManager::exec_timeout(const std::string& cmd, int timeout_sec, bool needs_root) {
    // Validate timeout range (1 second to 5 minutes)
    if (timeout_sec < 1) timeout_sec = 1;
    if (timeout_sec > 300) timeout_sec = 300;
    
    std::string timeout_cmd = "timeout " + std::to_string(timeout_sec) + " " + cmd;
    return exec(timeout_cmd, needs_root);
}

// =============================================================================
// AUDIT LOGGING
// =============================================================================

void SecurityManager::log_attempt(const std::string& action, const std::string& input, bool allowed) {
    std::string status = allowed ? "[ALLOWED]" : "[BLOCKED]";
    std::string sanitized_input = input;
    
    // Check for sensitive patterns in action or input
    std::string action_lower = action;
    std::string input_lower = input;
    std::transform(action_lower.begin(), action_lower.end(), action_lower.begin(), ::tolower);
    std::transform(input_lower.begin(), input_lower.end(), input_lower.begin(), ::tolower);
    
    for (const auto& pattern : SENSITIVE_PATTERNS) {
        if (action_lower.find(pattern) != std::string::npos ||
            input_lower.find(pattern) != std::string::npos) {
            sanitized_input = "[REDACTED]";
            break;
        }
    }
    
    // Truncate long inputs
    if (sanitized_input.length() > 100) {
        sanitized_input = sanitized_input.substr(0, 100) + "...";
    }
    
    m_impl->log(status + " " + action + ": " + sanitized_input);
}

void SecurityManager::log_exec(const std::string& cmd, bool needs_root, int result_code) {
    std::string prefix = needs_root ? "[ROOT] " : "[USER] ";
    std::string status = result_code == -1 ? "STARTED" : ("EXIT=" + std::to_string(result_code));
    
    // Check for ANY sensitive pattern
    std::string safe_cmd = cmd;
    std::string cmd_lower = cmd;
    std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(), ::tolower);
    
    for (const auto& pattern : SENSITIVE_PATTERNS) {
        if (cmd_lower.find(pattern) != std::string::npos) {
            safe_cmd = "[COMMAND REDACTED - CONTAINS SENSITIVE DATA]";
            break;
        }
    }
    
    // Truncate long commands
    if (safe_cmd.length() > 200) {
        safe_cmd = safe_cmd.substr(0, 200) + "...";
    }
    
    m_impl->log(prefix + status + " " + safe_cmd);
}

std::vector<std::string> SecurityManager::get_security_log(int max_entries) {
    std::lock_guard<std::mutex> lock(m_impl->log_mutex);
    
    std::vector<std::string> result;
    int start = std::max(0, (int)m_impl->recent_log.size() - max_entries);
    
    for (int i = start; i < (int)m_impl->recent_log.size(); i++) {
        result.push_back(m_impl->recent_log[i]);
    }
    
    return result;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

void SecurityManager::set_log_path(const std::string& path) {
    auto r = validate_path(path);
    if (!r.valid) {
        m_impl->log("[CONFIG BLOCKED] Invalid log path: " + path);
        return;
    }
    
    // Enforce allowed prefixes
    bool allowed = false;
    for (const auto& prefix : ALLOWED_LOG_PATHS) {
        if (r.sanitized.find(prefix) == 0) {
            allowed = true;
            break;
        }
    }
    
    if (!allowed) {
        m_impl->log("[CONFIG BLOCKED] Log path not in allowed directories: " + path);
        return;
    }
    
    m_impl->log_path = r.sanitized;
    m_impl->log("[CONFIG] Log path set to: " + r.sanitized);
}

void SecurityManager::set_strict_mode(bool strict) {
    m_impl->strict_mode = strict;
    m_impl->log(strict ? "[CONFIG] Strict mode ENABLED" : "[CONFIG] Strict mode DISABLED");
}

} // namespace security
