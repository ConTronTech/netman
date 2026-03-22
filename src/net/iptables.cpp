#include "iptables.hpp"
#include "../helpers/exec.hpp"
#include <sstream>
#include <regex>

namespace iptables {

std::string io_state_to_string(IOState state) {
    switch (state) {
        case IOState::BIDIRECTIONAL: return "Bidirectional";
        case IOState::INBOUND_ONLY: return "Inbound Only";
        case IOState::OUTBOUND_ONLY: return "Outbound Only";
        case IOState::BLOCKED: return "Blocked";
        default: return "Unknown";
    }
}

IOState string_to_io_state(const std::string& str) {
    if (str == "Bidirectional" || str == "bidirectional") return IOState::BIDIRECTIONAL;
    if (str == "Inbound Only" || str == "inbound") return IOState::INBOUND_ONLY;
    if (str == "Outbound Only" || str == "outbound") return IOState::OUTBOUND_ONLY;
    if (str == "Blocked" || str == "blocked") return IOState::BLOCKED;
    return IOState::BIDIRECTIONAL;
}

// Helper to run iptables with root
static bool run_iptables(const std::string& args) {
    auto result = exec::run_root("iptables " + args);
    return result.code == 0;
}

// Clear our custom rules for an interface
static void clear_io_rules(const std::string& iface) {
    // Delete any existing netman rules for this interface
    // We use a comment to identify our rules
    std::string comment = "netman-io-" + iface;
    
    // Try to delete until no more matching rules
    for (int i = 0; i < 10; i++) {
        auto result = exec::run_root(
            "iptables -D INPUT -i " + iface + " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null");
        if (result.code != 0) break;
    }
    for (int i = 0; i < 10; i++) {
        auto result = exec::run_root(
            "iptables -D OUTPUT -o " + iface + " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null");
        if (result.code != 0) break;
    }
}

bool set_io_state(const std::string& iface, IOState state) {
    std::string comment = "netman-io-" + iface;
    
    // First clear any existing rules
    clear_io_rules(iface);
    
    switch (state) {
        case IOState::BIDIRECTIONAL:
            // No rules needed - default allow
            return true;
            
        case IOState::INBOUND_ONLY:
            // Block outbound
            return run_iptables("-A OUTPUT -o " + iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            
        case IOState::OUTBOUND_ONLY:
            // Block inbound
            return run_iptables("-A INPUT -i " + iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            
        case IOState::BLOCKED:
            // Block both
            run_iptables("-A INPUT -i " + iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            run_iptables("-A OUTPUT -o " + iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            return true;
    }
    
    return false;
}

IOState get_io_state(const std::string& iface) {
    std::string comment = "netman-io-" + iface;
    
    // Check for our rules
    std::string input_check = exec::run("sudo iptables -C INPUT -i " + iface + 
        " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null && echo found");
    std::string output_check = exec::run("sudo iptables -C OUTPUT -o " + iface + 
        " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null && echo found");
    
    bool input_blocked = input_check.find("found") != std::string::npos;
    bool output_blocked = output_check.find("found") != std::string::npos;
    
    if (input_blocked && output_blocked) return IOState::BLOCKED;
    if (input_blocked) return IOState::OUTBOUND_ONLY;
    if (output_blocked) return IOState::INBOUND_ONLY;
    return IOState::BIDIRECTIONAL;
}

std::vector<Rule> list_rules(const std::string& table) {
    std::vector<Rule> rules;
    
    std::string output = exec::run("sudo iptables -t " + table + " -L -n --line-numbers 2>/dev/null");
    
    // Basic parsing - this is simplified
    // Full parsing would need -S format
    std::istringstream iss(output);
    std::string line;
    std::string current_chain;
    
    while (std::getline(iss, line)) {
        if (line.find("Chain ") == 0) {
            // Extract chain name
            size_t space = line.find(' ', 6);
            current_chain = line.substr(6, space - 6);
        }
        // Rule lines start with a number
        else if (!line.empty() && std::isdigit(line[0])) {
            Rule rule;
            rule.chain = current_chain;
            rule.dport = -1;
            rule.sport = -1;
            
            // Very basic parsing
            if (line.find("ACCEPT") != std::string::npos) rule.target = "ACCEPT";
            else if (line.find("DROP") != std::string::npos) rule.target = "DROP";
            else if (line.find("REJECT") != std::string::npos) rule.target = "REJECT";
            
            if (line.find("tcp") != std::string::npos) rule.protocol = "tcp";
            else if (line.find("udp") != std::string::npos) rule.protocol = "udp";
            else if (line.find("icmp") != std::string::npos) rule.protocol = "icmp";
            else rule.protocol = "all";
            
            rules.push_back(rule);
        }
    }
    
    return rules;
}

bool add_rule(const Rule& rule) {
    std::string cmd = "-A " + rule.chain;
    
    if (!rule.protocol.empty() && rule.protocol != "all") {
        cmd += " -p " + rule.protocol;
    }
    if (!rule.source.empty()) {
        cmd += " -s " + rule.source;
    }
    if (!rule.dest.empty()) {
        cmd += " -d " + rule.dest;
    }
    if (!rule.in_iface.empty()) {
        cmd += " -i " + rule.in_iface;
    }
    if (!rule.out_iface.empty()) {
        cmd += " -o " + rule.out_iface;
    }
    if (rule.dport > 0) {
        cmd += " --dport " + std::to_string(rule.dport);
    }
    if (rule.sport > 0) {
        cmd += " --sport " + std::to_string(rule.sport);
    }
    cmd += " -j " + rule.target;
    
    return run_iptables(cmd);
}

bool delete_rule(const Rule& rule) {
    std::string cmd = "-D " + rule.chain;
    
    if (!rule.protocol.empty() && rule.protocol != "all") {
        cmd += " -p " + rule.protocol;
    }
    if (!rule.source.empty()) {
        cmd += " -s " + rule.source;
    }
    if (!rule.dest.empty()) {
        cmd += " -d " + rule.dest;
    }
    if (!rule.in_iface.empty()) {
        cmd += " -i " + rule.in_iface;
    }
    if (!rule.out_iface.empty()) {
        cmd += " -o " + rule.out_iface;
    }
    if (rule.dport > 0) {
        cmd += " --dport " + std::to_string(rule.dport);
    }
    if (rule.sport > 0) {
        cmd += " --sport " + std::to_string(rule.sport);
    }
    cmd += " -j " + rule.target;
    
    return run_iptables(cmd);
}

bool flush_chain(const std::string& chain) {
    return run_iptables("-F " + chain);
}

bool save_rules(const std::string& filepath) {
    auto result = exec::run_root("iptables-save > " + filepath);
    return result.code == 0;
}

bool restore_rules(const std::string& filepath) {
    auto result = exec::run_root("iptables-restore < " + filepath);
    return result.code == 0;
}

} // namespace iptables
