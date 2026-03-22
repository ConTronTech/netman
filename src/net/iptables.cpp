#include "iptables.hpp"
#include "../core/security_manager.hpp"
#include <sstream>
#include <fstream>
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

// Helper to run iptables with validated table
static bool run_iptables(const std::string& args, const std::string& table = "filter") {
    // Validate table
    auto table_result = SEC.validate(security::InputType::TABLE, table);
    if (!table_result.valid) {
        SEC.log_attempt("run_iptables", "invalid table: " + table, false);
        return false;
    }
    
    std::string cmd = "iptables -t " + table_result.sanitized + " " + args;
    auto result = SEC.exec(cmd, true);
    return result.code == 0;
}

// Clear our custom rules for an interface
static void clear_io_rules(const std::string& iface) {
    // Interface already validated by caller
    std::string comment = "netman-io-" + iface;
    
    // Try to delete until no more matching rules (max 10 iterations for safety)
    for (int i = 0; i < 10; i++) {
        auto result = SEC.exec(
            "iptables -D INPUT -i " + iface + " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null",
            true);
        if (result.code != 0) break;
    }
    for (int i = 0; i < 10; i++) {
        auto result = SEC.exec(
            "iptables -D OUTPUT -o " + iface + " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null",
            true);
        if (result.code != 0) break;
    }
}

bool set_io_state(const std::string& iface, IOState state) {
    // Validate interface
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) {
        SEC.log_attempt("set_io_state", "invalid interface: " + iface, false);
        return false;
    }
    
    std::string comment = "netman-io-" + safe_iface;
    
    // First clear any existing rules
    clear_io_rules(safe_iface);
    
    switch (state) {
        case IOState::BIDIRECTIONAL:
            // No rules needed - default allow
            return true;
            
        case IOState::INBOUND_ONLY:
            // Block outbound
            return run_iptables("-A OUTPUT -o " + safe_iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            
        case IOState::OUTBOUND_ONLY:
            // Block inbound
            return run_iptables("-A INPUT -i " + safe_iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            
        case IOState::BLOCKED:
            // Block both
            run_iptables("-A INPUT -i " + safe_iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            run_iptables("-A OUTPUT -o " + safe_iface + 
                " -m comment --comment \"" + comment + "\" -j DROP");
            return true;
    }
    
    return false;
}

IOState get_io_state(const std::string& iface) {
    // Validate interface
    std::string safe_iface = SEC.safe_interface(iface);
    if (safe_iface.empty()) {
        return IOState::BIDIRECTIONAL;
    }
    
    std::string comment = "netman-io-" + safe_iface;
    
    // Check for our rules
    auto input_check = SEC.exec(
        "iptables -C INPUT -i " + safe_iface + 
        " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null && echo found",
        true);
    auto output_check = SEC.exec(
        "iptables -C OUTPUT -o " + safe_iface + 
        " -m comment --comment \"" + comment + "\" -j DROP 2>/dev/null && echo found",
        true);
    
    bool input_blocked = input_check.out.find("found") != std::string::npos;
    bool output_blocked = output_check.out.find("found") != std::string::npos;
    
    if (input_blocked && output_blocked) return IOState::BLOCKED;
    if (input_blocked) return IOState::OUTBOUND_ONLY;
    if (output_blocked) return IOState::INBOUND_ONLY;
    return IOState::BIDIRECTIONAL;
}

// Validate a complete Rule struct
static bool validate_rule(const Rule& rule, Rule& safe_rule) {
    // Chain (required)
    auto chain_result = SEC.validate(security::InputType::CHAIN, rule.chain);
    if (!chain_result.valid) {
        SEC.log_attempt("validate_rule", "invalid chain: " + rule.chain, false);
        return false;
    }
    safe_rule.chain = chain_result.sanitized;
    
    // Target (required)
    std::string target_upper = rule.target;
    std::transform(target_upper.begin(), target_upper.end(), target_upper.begin(), ::toupper);
    if (target_upper != "ACCEPT" && target_upper != "DROP" && 
        target_upper != "REJECT" && target_upper != "LOG" &&
        target_upper != "RETURN" && target_upper != "MASQUERADE" &&
        target_upper != "SNAT" && target_upper != "DNAT") {
        // Could be a custom chain, validate as chain name
        auto target_chain = SEC.validate(security::InputType::CHAIN, rule.target);
        if (!target_chain.valid) {
            SEC.log_attempt("validate_rule", "invalid target: " + rule.target, false);
            return false;
        }
        safe_rule.target = target_chain.sanitized;
    } else {
        safe_rule.target = target_upper;
    }
    
    // Protocol (optional)
    if (!rule.protocol.empty()) {
        auto proto_result = SEC.validate(security::InputType::PROTOCOL, rule.protocol);
        if (!proto_result.valid) {
            SEC.log_attempt("validate_rule", "invalid protocol: " + rule.protocol, false);
            return false;
        }
        safe_rule.protocol = proto_result.sanitized;
    }
    
    // Source IP/CIDR (optional)
    if (!rule.source.empty()) {
        auto src_result = SEC.validate(security::InputType::IP_CIDR, rule.source);
        if (!src_result.valid) {
            SEC.log_attempt("validate_rule", "invalid source: " + rule.source, false);
            return false;
        }
        safe_rule.source = src_result.sanitized;
    }
    
    // Destination IP/CIDR (optional)
    if (!rule.dest.empty()) {
        auto dest_result = SEC.validate(security::InputType::IP_CIDR, rule.dest);
        if (!dest_result.valid) {
            SEC.log_attempt("validate_rule", "invalid dest: " + rule.dest, false);
            return false;
        }
        safe_rule.dest = dest_result.sanitized;
    }
    
    // Input interface (optional)
    if (!rule.in_iface.empty()) {
        std::string safe_in = SEC.safe_interface(rule.in_iface);
        if (safe_in.empty()) {
            SEC.log_attempt("validate_rule", "invalid in_iface: " + rule.in_iface, false);
            return false;
        }
        safe_rule.in_iface = safe_in;
    }
    
    // Output interface (optional)
    if (!rule.out_iface.empty()) {
        std::string safe_out = SEC.safe_interface(rule.out_iface);
        if (safe_out.empty()) {
            SEC.log_attempt("validate_rule", "invalid out_iface: " + rule.out_iface, false);
            return false;
        }
        safe_rule.out_iface = safe_out;
    }
    
    // Ports (optional)
    if (rule.dport > 0) {
        if (rule.dport < 1 || rule.dport > 65535) {
            SEC.log_attempt("validate_rule", "invalid dport: " + std::to_string(rule.dport), false);
            return false;
        }
        safe_rule.dport = rule.dport;
    }
    if (rule.sport > 0) {
        if (rule.sport < 1 || rule.sport > 65535) {
            SEC.log_attempt("validate_rule", "invalid sport: " + std::to_string(rule.sport), false);
            return false;
        }
        safe_rule.sport = rule.sport;
    }
    
    return true;
}

// Build iptables command from validated rule
static std::string build_rule_cmd(const Rule& rule, const std::string& action) {
    std::string cmd = action + " " + rule.chain;
    
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
    
    return cmd;
}

std::vector<Rule> list_rules(const std::string& table) {
    std::vector<Rule> rules;
    
    // Validate table
    auto table_result = SEC.validate(security::InputType::TABLE, table);
    if (!table_result.valid) {
        SEC.log_attempt("list_rules", "invalid table: " + table, false);
        return rules;
    }
    
    auto result = SEC.exec("iptables -t " + table_result.sanitized + " -L -n --line-numbers", true);
    
    // Basic parsing - this is simplified
    std::istringstream iss(result.out);
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
            else if (line.find("MASQUERADE") != std::string::npos) rule.target = "MASQUERADE";
            
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
    Rule safe_rule;
    if (!validate_rule(rule, safe_rule)) {
        return false;
    }
    
    std::string cmd = build_rule_cmd(safe_rule, "-A");
    return run_iptables(cmd);
}

bool delete_rule(const Rule& rule) {
    Rule safe_rule;
    if (!validate_rule(rule, safe_rule)) {
        return false;
    }
    
    std::string cmd = build_rule_cmd(safe_rule, "-D");
    return run_iptables(cmd);
}

bool flush_chain(const std::string& chain) {
    // Validate chain
    auto chain_result = SEC.validate(security::InputType::CHAIN, chain);
    if (!chain_result.valid) {
        SEC.log_attempt("flush_chain", "invalid chain: " + chain, false);
        return false;
    }
    
    return run_iptables("-F " + chain_result.sanitized);
}

bool save_rules(const std::string& filepath) {
    // Validate path - must be under allowed directory
    std::string safe_path = SEC.safe_path(filepath, "/tmp/netman");
    if (safe_path.empty()) {
        // Also allow /etc/iptables
        safe_path = SEC.safe_path(filepath, "/etc/iptables");
    }
    if (safe_path.empty()) {
        SEC.log_attempt("save_rules", "invalid path: " + filepath, false);
        return false;
    }
    
    // Run iptables-save and capture output, then write to file in C++
    // (Shell redirection blocked by SecurityManager)
    auto result = SEC.exec("iptables-save", true);
    if (result.code != 0) {
        SEC.log_attempt("save_rules", "iptables-save failed", false);
        return false;
    }
    
    try {
        std::ofstream out(safe_path);
        if (!out) {
            SEC.log_attempt("save_rules", "failed to open: " + safe_path, false);
            return false;
        }
        out << result.out;
        out.close();
        return true;
    } catch (...) {
        SEC.log_attempt("save_rules", "write error: " + safe_path, false);
        return false;
    }
}

bool restore_rules(const std::string& filepath) {
    // NOTE: Bulk restore is dangerous - disabled for security
    // Instead, use apply_rule() to add rules one by one
    // Or implement a parser that validates each rule before applying
    
    SEC.log_attempt("restore_rules", "bulk restore disabled for security", false);
    (void)filepath;  // Suppress unused warning
    return false;
    
    // TODO: Implement safe restore by:
    // 1. Read file
    // 2. Parse each rule
    // 3. Validate via SecurityManager
    // 4. Apply one by one with apply_rule()
}

} // namespace iptables
