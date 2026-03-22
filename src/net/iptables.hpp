#pragma once

#include <string>
#include <vector>

namespace iptables {

enum class IOState {
    BIDIRECTIONAL,  // Normal, no restrictions
    INBOUND_ONLY,   // Can receive, can't send
    OUTBOUND_ONLY,  // Can send, can't receive
    BLOCKED         // No traffic either way
};

// Per-interface I/O control
bool set_io_state(const std::string& iface, IOState state);
IOState get_io_state(const std::string& iface);

// Convert state to/from string
std::string io_state_to_string(IOState state);
IOState string_to_io_state(const std::string& str);

// Rule management
struct Rule {
    std::string chain;      // INPUT, OUTPUT, FORWARD
    std::string protocol;   // tcp, udp, icmp, all
    std::string source;     // IP/CIDR or empty
    std::string dest;       // IP/CIDR or empty
    std::string in_iface;   // Input interface
    std::string out_iface;  // Output interface
    int dport;              // Destination port (-1 = any)
    int sport;              // Source port (-1 = any)
    std::string target;     // ACCEPT, DROP, REJECT
};

// List current rules
std::vector<Rule> list_rules(const std::string& table = "filter");

// Add/remove rules
bool add_rule(const Rule& rule);
bool delete_rule(const Rule& rule);

// Flush all rules (dangerous!)
bool flush_chain(const std::string& chain);

// Save/restore
bool save_rules(const std::string& filepath);
bool restore_rules(const std::string& filepath);

} // namespace iptables
