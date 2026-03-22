#pragma once

#include <string>
#include <vector>
#include <functional>
#include <optional>

namespace security {

// =============================================================================
// VALIDATION RESULTS
// =============================================================================

struct ValidationResult {
    bool valid = false;
    std::string sanitized;      // Sanitized value (empty if invalid)
    std::string error;          // Error message if invalid
    
    operator bool() const { return valid; }
};

// =============================================================================
// INPUT TYPES - Each has specific validation rules
// =============================================================================

enum class InputType {
    INTERFACE,      // Network interface name (e.g., wlan0, eth0)
    MAC_ADDRESS,    // MAC address (AA:BB:CC:DD:EE:FF)
    IP_ADDRESS,     // IPv4 address
    IP_CIDR,        // IPv4 with CIDR (192.168.1.0/24)
    HOSTNAME,       // DNS hostname
    SSID,           // WiFi SSID (max 32 chars, printable)
    PASSWORD,       // WPA password (8-63 chars, printable)
    PATH,           // Filesystem path (no traversal)
    COUNTRY_CODE,   // 2-letter country code (whitelist)
    PORT,           // TCP/UDP port (1-65535)
    CHAIN,          // iptables chain name
    TABLE,          // iptables table name
    PROTOCOL,       // Network protocol (tcp, udp, icmp, all)
    CHANNEL,        // WiFi channel
    BAND,           // WiFi band (2.4, 5)
    SHELL_ARG,      // Generic shell argument (strict alphanumeric)
};

// =============================================================================
// SECURITY MANAGER - Singleton
// =============================================================================

class SecurityManager {
public:
    static SecurityManager& instance();
    
    // -------------------------------------------------------------------------
    // VALIDATION - Returns sanitized value or error
    // -------------------------------------------------------------------------
    
    ValidationResult validate(InputType type, const std::string& input);
    
    // Convenience validators (return empty string on failure)
    std::string safe_interface(const std::string& iface);
    std::string safe_mac(const std::string& mac);
    std::string safe_ip(const std::string& ip);
    std::string safe_path(const std::string& path, const std::string& allowed_prefix = "");
    std::string safe_ssid(const std::string& ssid);
    std::string safe_password(const std::string& pass);
    std::string safe_shell(const std::string& arg);
    
    // -------------------------------------------------------------------------
    // PRIVILEGE MANAGEMENT
    // -------------------------------------------------------------------------
    
    bool is_root();
    bool can_elevate();
    
    // -------------------------------------------------------------------------
    // SECURE EXECUTION - All shell commands go through here
    // -------------------------------------------------------------------------
    
    struct ExecResult {
        int code = -1;
        std::string out;
        std::string err;
    };
    
    // Execute with automatic privilege handling
    // If needs_root=true and not root, will fail (no silent elevation)
    ExecResult exec(const std::string& cmd, bool needs_root = false);
    
    // Execute with timeout (seconds)
    ExecResult exec_timeout(const std::string& cmd, int timeout_sec, bool needs_root = false);
    
    // -------------------------------------------------------------------------
    // AUDIT LOGGING
    // -------------------------------------------------------------------------
    
    void log_attempt(const std::string& action, const std::string& input, bool allowed);
    void log_exec(const std::string& cmd, bool needs_root, int result_code);
    
    // Get recent suspicious activity
    std::vector<std::string> get_security_log(int max_entries = 50);
    
    // -------------------------------------------------------------------------
    // CONFIGURATION
    // -------------------------------------------------------------------------
    
    void set_log_path(const std::string& path);
    void set_strict_mode(bool strict);  // Reject anything suspicious vs. sanitize
    
private:
    SecurityManager();
    ~SecurityManager();
    SecurityManager(const SecurityManager&) = delete;
    SecurityManager& operator=(const SecurityManager&) = delete;
    
    // Internal validators
    ValidationResult validate_interface(const std::string& input);
    ValidationResult validate_mac(const std::string& input);
    ValidationResult validate_ip(const std::string& input);
    ValidationResult validate_ip_cidr(const std::string& input);
    ValidationResult validate_hostname(const std::string& input);
    ValidationResult validate_ssid(const std::string& input);
    ValidationResult validate_password(const std::string& input);
    ValidationResult validate_path(const std::string& input);
    ValidationResult validate_country(const std::string& input);
    ValidationResult validate_port(const std::string& input);
    ValidationResult validate_chain(const std::string& input);
    ValidationResult validate_table(const std::string& input);
    ValidationResult validate_protocol(const std::string& input);
    ValidationResult validate_channel(const std::string& input);
    ValidationResult validate_band(const std::string& input);
    ValidationResult validate_shell_arg(const std::string& input);
    
    struct Impl;
    Impl* m_impl;
};

// =============================================================================
// CONVENIENCE MACROS
// =============================================================================

#define SEC security::SecurityManager::instance()

// Validate and get sanitized value, return early with error if invalid
#define VALIDATE_OR_FAIL(type, input, var) \
    auto var##_result = SEC.validate(type, input); \
    if (!var##_result) { \
        return {false, var##_result.error}; \
    } \
    std::string var = var##_result.sanitized;

// Validate or return empty optional
#define VALIDATE_OR_EMPTY(type, input, var) \
    auto var##_result = SEC.validate(type, input); \
    if (!var##_result) return std::nullopt; \
    std::string var = var##_result.sanitized;

} // namespace security
