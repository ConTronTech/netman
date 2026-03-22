#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace interfaces {

struct Interface {
    std::string name;       // "wlan0"
    std::string state;      // "UP" / "DOWN"
    std::string ip;         // "192.168.1.212" or ""
    std::string mac;        // "AA:BB:CC:DD:EE:FF"
    std::string gateway;    // "192.168.1.1" or ""
    uint64_t rx_bytes;      // bytes received
    uint64_t tx_bytes;      // bytes sent
    int signal;             // wifi signal % (-1 if not wifi)
};

// Get all network interfaces
std::vector<Interface> list();

// Get specific interface
Interface get(const std::string& name);

// Enable/disable interface
bool set_state(const std::string& name, bool up);

// Get current DNS server
std::string get_dns();

// Get default gateway
std::string get_default_gateway();

} // namespace interfaces
