#include "scanner.hpp"
#include "interfaces.hpp"
#include "../core/security_manager.hpp"
#include <regex>
#include <sstream>
#include <algorithm>

namespace scanner {

std::string resolve_hostname(const std::string& ip) {
    // Validate IP first
    std::string safe_ip = SEC.safe_ip(ip);
    if (safe_ip.empty()) {
        return "";
    }
    
    auto result = SEC.exec_timeout("getent hosts " + safe_ip, 5, false);
    if (!result.out.empty()) {
        std::istringstream iss(result.out);
        std::string addr, hostname;
        iss >> addr >> hostname;
        if (!hostname.empty() && hostname != safe_ip) {
            // Sanitize hostname output
            auto host_result = SEC.validate(security::InputType::HOSTNAME, hostname);
            if (host_result.valid) {
                return host_result.sanitized;
            }
        }
    }
    return "";
}

std::vector<Device> quick_scan() {
    std::vector<Device> devices;
    
    // Get our own IPs/MACs for is_self detection
    auto our_ifaces = interfaces::list();
    
    // Use ip neigh (ARP table) - no user input, safe command
    auto neigh_result = SEC.exec("ip neigh show", false);
    std::istringstream iss(neigh_result.out);
    std::string line;
    
    // Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    std::regex neigh_regex(R"((\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+))");
    
    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, neigh_regex)) {
            Device dev;
            
            // Validate IP
            std::string ip_candidate = match[1];
            std::string safe_ip = SEC.safe_ip(ip_candidate);
            if (safe_ip.empty()) continue;
            dev.ip = safe_ip;
            
            // Validate MAC
            std::string mac_candidate = match[2];
            std::string safe_mac = SEC.safe_mac(mac_candidate);
            if (safe_mac.empty()) continue;
            dev.mac = safe_mac;
            
            // Check if this is us
            dev.is_self = false;
            for (const auto& iface : our_ifaces) {
                if (iface.ip == dev.ip || iface.mac == dev.mac) {
                    dev.is_self = true;
                    break;
                }
            }
            
            // Try to resolve hostname
            dev.hostname = resolve_hostname(dev.ip);
            
            devices.push_back(dev);
        }
    }
    
    // Add our own interfaces
    for (const auto& iface : our_ifaces) {
        if (!iface.ip.empty()) {
            Device self;
            self.ip = iface.ip;
            self.mac = iface.mac;
            self.hostname = "localhost";
            self.is_self = true;
            
            // Check if already in list
            bool exists = false;
            for (const auto& d : devices) {
                if (d.ip == self.ip) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                devices.push_back(self);
            }
        }
    }
    
    return devices;
}

std::vector<Device> arp_scan(const std::string& interface) {
    std::vector<Device> devices;
    
    // Validate interface
    std::string safe_iface = SEC.safe_interface(interface);
    if (safe_iface.empty()) {
        SEC.log_attempt("arp_scan", "invalid interface: " + interface, false);
        return quick_scan();  // Fallback
    }
    
    // Get our own IPs/MACs
    auto our_ifaces = interfaces::list();
    
    // Check if arp-scan exists first
    auto which_result = SEC.exec("which arp-scan", false);
    bool has_arp_scan = (which_result.code == 0 && !which_result.out.empty());
    
    if (has_arp_scan) {
        // Run arp-scan with validated interface
        auto scan_result = SEC.exec_timeout("arp-scan -l -I " + safe_iface, 30, true);
        
        if (!scan_result.out.empty() && scan_result.out.find("Starting arp-scan") != std::string::npos) {
            // Parse arp-scan output
            // Format: 192.168.1.1    aa:bb:cc:dd:ee:ff    Vendor Name
            std::regex arp_regex(R"((\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s*(.*))");
            std::istringstream iss(scan_result.out);
            std::string line;
            
            while (std::getline(iss, line)) {
                std::smatch match;
                if (std::regex_search(line, match, arp_regex)) {
                    Device dev;
                    
                    // Validate IP
                    std::string ip_candidate = match[1];
                    std::string safe_ip = SEC.safe_ip(ip_candidate);
                    if (safe_ip.empty()) continue;
                    dev.ip = safe_ip;
                    
                    // Validate MAC
                    std::string mac_candidate = match[2];
                    std::string safe_mac = SEC.safe_mac(mac_candidate);
                    if (safe_mac.empty()) continue;
                    dev.mac = safe_mac;
                    
                    // Sanitize vendor string
                    std::string vendor_raw = match[3];
                    std::string vendor_clean;
                    for (char c : vendor_raw) {
                        if (c >= 32 && c < 127 && c != '\t') {
                            vendor_clean += c;
                        } else if (c == '\t') {
                            break;  // Stop at first tab
                        }
                    }
                    dev.vendor = vendor_clean;
                    
                    // Check if this is us
                    dev.is_self = false;
                    for (const auto& iface : our_ifaces) {
                        if (iface.ip == dev.ip || iface.mac == dev.mac) {
                            dev.is_self = true;
                            break;
                        }
                    }
                    
                    dev.hostname = resolve_hostname(dev.ip);
                    devices.push_back(dev);
                }
            }
        }
    }
    
    // If arp-scan didn't work or returned nothing, fall back to ping sweep + quick_scan
    if (devices.empty()) {
        auto iface = interfaces::get(safe_iface);
        if (!iface.ip.empty()) {
            // Extract network from IP (assume /24)
            // IP is already validated
            size_t last_dot = iface.ip.rfind('.');
            if (last_dot != std::string::npos) {
                std::string network = iface.ip.substr(0, last_dot + 1);
                
                // Quick ping sweep (background, don't wait)
                // Network prefix is derived from validated IP, safe to use
                for (int i = 1; i <= 254; i++) {
                    std::string target_ip = network + std::to_string(i);
                    // Double-validate the constructed IP
                    if (!SEC.safe_ip(target_ip).empty()) {
                        SEC.exec("ping -c 1 -W 1 " + target_ip + " >/dev/null 2>&1 &", false);
                    }
                }
                
                // Wait a moment for ARP table to populate
                SEC.exec("sleep 2", false);
            }
        }
        
        devices = quick_scan();
    }
    
    // Sort by IP
    std::sort(devices.begin(), devices.end(), [](const Device& a, const Device& b) {
        // Simple IP comparison (works for same subnet)
        auto get_last_octet = [](const std::string& ip) -> int {
            size_t pos = ip.rfind('.');
            if (pos == std::string::npos) return 0;
            try {
                return std::stoi(ip.substr(pos + 1));
            } catch (...) {
                return 0;
            }
        };
        return get_last_octet(a.ip) < get_last_octet(b.ip);
    });
    
    return devices;
}

} // namespace scanner
