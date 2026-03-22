#pragma once

#include <gtkmm.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include "../net/interfaces.hpp"
#include "../net/scanner.hpp"

// Central state manager with cached data + background refresh
// UI reads from cache (instant), background updates cache periodically

class AppState {
public:
    static AppState& instance() {
        static AppState inst;
        return inst;
    }
    
    // Start/stop background refresh
    void start();
    void stop();
    
    // === Cached Data (thread-safe reads) ===
    
    // Interfaces
    std::vector<interfaces::Interface> get_interfaces();
    interfaces::Interface get_interface(const std::string& name);
    std::string get_gateway();
    std::string get_dns();
    
    // Devices (from last scan)
    std::vector<scanner::Device> get_devices();
    void request_device_scan();  // Trigger async scan
    
    // Network status
    bool has_internet();
    bool is_captive_portal();
    
    // Bandwidth (calculated from interface deltas)
    uint64_t get_rx_speed();  // bytes/sec
    uint64_t get_tx_speed();
    
    // === Signals (connect UI to updates) ===
    using UpdateSignal = sigc::signal<void()>;
    
    UpdateSignal signal_interfaces_changed();
    UpdateSignal signal_devices_changed();
    UpdateSignal signal_network_status_changed();
    UpdateSignal signal_bandwidth_changed();
    
private:
    AppState();
    ~AppState();
    
    void refresh_loop();
    void refresh_interfaces();
    void refresh_network_status();
    void do_device_scan();
    
    // Background thread
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    
    // Cached data with mutex protection
    std::mutex m_mutex;
    std::vector<interfaces::Interface> m_interfaces;
    std::vector<interfaces::Interface> m_prev_interfaces;  // For bandwidth calc
    std::vector<scanner::Device> m_devices;
    std::string m_gateway;
    std::string m_dns;
    bool m_has_internet{false};
    bool m_is_captive{false};
    uint64_t m_rx_speed{0};
    uint64_t m_tx_speed{0};
    
    // Scan request flag
    std::atomic<bool> m_scan_requested{false};
    
    // Signals
    UpdateSignal m_sig_interfaces;
    UpdateSignal m_sig_devices;
    UpdateSignal m_sig_network;
    UpdateSignal m_sig_bandwidth;
    
    // Emit signal on main thread
    void emit_on_main(UpdateSignal& sig);
};

// Convenience macro
#define STATE AppState::instance()
