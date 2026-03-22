#include "scanner.hpp"
#include "interfaces.hpp"
#include "../helpers/exec.hpp"
#include <regex>
#include <sstream>
#include <algorithm>

namespace scanner {

std::string resolve_hostname(const std::string& ip) {
    std::string output = exec::run("getent hosts " + ip + " 2>/dev/null");
    if (!output.empty()) {
        std::istringstream iss(output);
        std::string addr, hostname;
        iss >> addr >> hostname;
        if (!hostname.empty() && hostname != ip) {
            return hostname;
        }
    }
    return "";
}

std::vector<Device> quick_scan() {
    std::vector<Device> devices;
    
    // Get our own IPs/MACs for is_self detection
    auto our_ifaces = interfaces::list();
    
    // Use ip neigh (ARP table)
    std::string output = exec::run("ip neigh show 2>/dev/null");
    std::istringstream iss(output);
    std::string line;
    
    // Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    std::regex neigh_regex(R"((\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+))");
    
    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, neigh_regex)) {
            Device dev;
            dev.ip = match[1];
            dev.mac = match[2];
            
            // Uppercase MAC
            std::transform(dev.mac.begin(), dev.mac.end(), 
                           dev.mac.begin(), ::toupper);
            
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
    
    // Get our own IPs/MACs
    auto our_ifaces = interfaces::list();
    
    // Try arp-scan first (needs root)
    std::string output = exec::run("which arp-scan >/dev/null 2>&1 && sudo arp-scan -l -I " + interface + " 2>/dev/null");
    
    if (!output.empty() && output.find("Starting arp-scan") != std::string::npos) {
        // Parse arp-scan output
        // Format: 192.168.1.1    aa:bb:cc:dd:ee:ff    Vendor Name
        std::regex arp_regex(R"((\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s*(.*))");
        std::istringstream iss(output);
        std::string line;
        
        while (std::getline(iss, line)) {
            std::smatch match;
            if (std::regex_search(line, match, arp_regex)) {
                Device dev;
                dev.ip = match[1];
                dev.mac = match[2];
                dev.vendor = match[3];
                
                // Uppercase MAC
                std::transform(dev.mac.begin(), dev.mac.end(), 
                               dev.mac.begin(), ::toupper);
                
                // Clean vendor string
                size_t pos = dev.vendor.find_first_of("\t\n");
                if (pos != std::string::npos) {
                    dev.vendor = dev.vendor.substr(0, pos);
                }
                
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
    
    // If arp-scan didn't work or returned nothing, fall back to quick_scan
    if (devices.empty()) {
        // Ping sweep to populate ARP table, then quick_scan
        auto iface = interfaces::get(interface);
        if (!iface.ip.empty()) {
            // Extract network from IP (assume /24)
            std::string network = iface.ip.substr(0, iface.ip.rfind('.')) + ".";
            
            // Quick ping sweep (background, don't wait)
            for (int i = 1; i <= 254; i++) {
                exec::run("ping -c 1 -W 1 " + network + std::to_string(i) + " >/dev/null 2>&1 &");
            }
            
            // Wait a moment for ARP table to populate
            exec::run("sleep 2");
        }
        
        devices = quick_scan();
    }
    
    // Sort by IP
    std::sort(devices.begin(), devices.end(), [](const Device& a, const Device& b) {
        // Simple IP comparison (works for same subnet)
        auto get_last_octet = [](const std::string& ip) {
            size_t pos = ip.rfind('.');
            return pos != std::string::npos ? std::stoi(ip.substr(pos + 1)) : 0;
        };
        return get_last_octet(a.ip) < get_last_octet(b.ip);
    });
    
    return devices;
}

} // namespace scanner
