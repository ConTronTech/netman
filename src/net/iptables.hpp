#pragma once

#include <string>
#include <vector>
#include <optional>

namespace iptables {

// === Enums for type-safe command building ===

enum class IOState {
    BIDIRECTIONAL,  // Normal, no restrictions
    INBOUND_ONLY,   // Can receive, can't send
    OUTBOUND_ONLY,  // Can send, can't receive
    BLOCKED         // No traffic either way
};

enum class Action {
    APPEND,   // -A (add to end)
    INSERT,   // -I (add to start)
    DELETE,   // -D (remove)
    CHECK,    // -C (check exists)
    LIST,     // -L (list rules)
    SAVE,     // -S (print rules)
};

enum class Table {
    FILTER,   // Default table
    NAT,      // NAT table
    MANGLE,   // Packet mangling
    RAW,      // Raw packets
};

enum class Chain {
    INPUT,
    OUTPUT,
    FORWARD,
    PREROUTING,   // NAT only
    POSTROUTING,  // NAT only
};

enum class Target {
    ACCEPT,
    DROP,
    REJECT,
    LOG,
    MASQUERADE,   // NAT
    SNAT,         // NAT
    DNAT,         // NAT
    REDIRECT,     // NAT
};

enum class Protocol {
    TCP,
    UDP,
    ICMP,
    ALL,
};

// Per-interface I/O control
bool set_io_state(const std::string& iface, IOState state);
IOState get_io_state(const std::string& iface);

// Convert state to/from string
std::string io_state_to_string(IOState state);
IOState string_to_io_state(const std::string& str);

// Rule struct for legacy code
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

// === Type-safe command builder ===
// Builds validated iptables commands programmatically

class CommandBuilder {
public:
    CommandBuilder();
    
    // Required
    CommandBuilder& action(Action a);
    CommandBuilder& chain(Chain c);
    
    // Optional
    CommandBuilder& table(Table t);
    CommandBuilder& target(Target t);
    CommandBuilder& protocol(Protocol p);
    CommandBuilder& source(const std::string& ip_cidr);
    CommandBuilder& destination(const std::string& ip_cidr);
    CommandBuilder& in_interface(const std::string& iface);
    CommandBuilder& out_interface(const std::string& iface);
    CommandBuilder& sport(int port);
    CommandBuilder& dport(int port);
    CommandBuilder& comment(const std::string& text);
    
    // Build and execute
    std::string build() const;           // Returns command string (for preview)
    bool execute();                       // Validates and runs
    bool dry_run() const;                 // Logs but doesn't execute
    
    // Reset for reuse
    void reset();
    
    // Get last error
    std::string last_error() const { return m_error; }
    
private:
    std::optional<Action> m_action;
    std::optional<Chain> m_chain;
    Table m_table = Table::FILTER;
    std::optional<Target> m_target;
    std::optional<Protocol> m_protocol;
    std::string m_source;
    std::string m_dest;
    std::string m_in_iface;
    std::string m_out_iface;
    int m_sport = -1;
    int m_dport = -1;
    std::string m_comment;
    mutable std::string m_error;
    
    bool validate() const;
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
