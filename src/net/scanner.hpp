#pragma once

#include <string>
#include <vector>

namespace scanner {

struct Device {
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string vendor;     // From MAC OUI (optional)
    bool is_self;           // This machine
};

// ARP scan the local network on given interface
// Uses arp-scan if available, falls back to ip neigh
std::vector<Device> arp_scan(const std::string& interface);

// Quick scan using ip neigh (no root needed)
std::vector<Device> quick_scan();

// Get hostname for IP via reverse DNS
std::string resolve_hostname(const std::string& ip);

} // namespace scanner
