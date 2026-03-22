#include "state.hpp"
#include "../helpers/exec.hpp"
#include <chrono>

AppState::AppState() {}

AppState::~AppState() {
    stop();
}

void AppState::start() {
    if (m_running) return;
    
    m_running = true;
    
    // Initial sync refresh
    refresh_interfaces();
    
    // Start background thread
    m_thread = std::thread(&AppState::refresh_loop, this);
}

void AppState::stop() {
    m_running = false;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void AppState::refresh_loop() {
    int tick = 0;
    
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!m_running) break;
        
        // Every 1 sec: interfaces + bandwidth
        refresh_interfaces();
        
        // Every 10 sec: network status (slow)
        if (tick % 10 == 0) {
            refresh_network_status();
        }
        
        // Check for device scan request
        if (m_scan_requested) {
            m_scan_requested = false;
            do_device_scan();
        }
        
        tick++;
    }
}

void AppState::refresh_interfaces() {
    auto new_ifaces = interfaces::list();
    std::string new_gw = interfaces::get_default_gateway();
    std::string new_dns = interfaces::get_dns();
    
    uint64_t total_rx = 0, total_tx = 0;
    uint64_t prev_rx = 0, prev_tx = 0;
    
    // Calculate bandwidth from deltas
    for (const auto& iface : new_ifaces) {
        total_rx += iface.rx_bytes;
        total_tx += iface.tx_bytes;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (const auto& iface : m_prev_interfaces) {
            prev_rx += iface.rx_bytes;
            prev_tx += iface.tx_bytes;
        }
        
        if (prev_rx > 0 && total_rx >= prev_rx) {
            m_rx_speed = total_rx - prev_rx;
        }
        if (prev_tx > 0 && total_tx >= prev_tx) {
            m_tx_speed = total_tx - prev_tx;
        }
        
        // Check if interfaces changed
        bool changed = (new_ifaces.size() != m_interfaces.size());
        if (!changed) {
            for (size_t i = 0; i < new_ifaces.size(); i++) {
                if (new_ifaces[i].name != m_interfaces[i].name ||
                    new_ifaces[i].state != m_interfaces[i].state ||
                    new_ifaces[i].ip != m_interfaces[i].ip) {
                    changed = true;
                    break;
                }
            }
        }
        
        m_prev_interfaces = m_interfaces;
        m_interfaces = new_ifaces;
        m_gateway = new_gw;
        m_dns = new_dns;
        
        if (changed) {
            emit_on_main(m_sig_interfaces);
        }
    }
    
    emit_on_main(m_sig_bandwidth);
}

void AppState::refresh_network_status() {
    // These are slow - curl calls
    bool has_net = false;
    bool captive = false;
    
    auto result = exec::run("curl -s --connect-timeout 3 --max-time 5 http://captive.apple.com/hotspot-detect.html 2>/dev/null");
    
    if (result.find("Success") != std::string::npos) {
        has_net = true;
        captive = false;
    } else if (result.find("<html") != std::string::npos ||
               result.find("captive") != std::string::npos) {
        has_net = true;
        captive = true;
    }
    
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_has_internet != has_net || m_is_captive != captive) {
            changed = true;
        }
        m_has_internet = has_net;
        m_is_captive = captive;
    }
    
    if (changed) {
        emit_on_main(m_sig_network);
    }
}

void AppState::do_device_scan() {
    auto devices = scanner::quick_scan();
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_devices = devices;
    }
    
    emit_on_main(m_sig_devices);
}

void AppState::request_device_scan() {
    m_scan_requested = true;
}

// === Getters (thread-safe) ===

std::vector<interfaces::Interface> AppState::get_interfaces() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_interfaces;
}

interfaces::Interface AppState::get_interface(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& iface : m_interfaces) {
        if (iface.name == name) return iface;
    }
    return {};
}

std::string AppState::get_gateway() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_gateway;
}

std::string AppState::get_dns() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dns;
}

std::vector<scanner::Device> AppState::get_devices() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_devices;
}

bool AppState::has_internet() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_has_internet;
}

bool AppState::is_captive_portal() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_is_captive;
}

uint64_t AppState::get_rx_speed() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_rx_speed;
}

uint64_t AppState::get_tx_speed() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tx_speed;
}

// === Signals ===

AppState::UpdateSignal AppState::signal_interfaces_changed() {
    return m_sig_interfaces;
}

AppState::UpdateSignal AppState::signal_devices_changed() {
    return m_sig_devices;
}

AppState::UpdateSignal AppState::signal_network_status_changed() {
    return m_sig_network;
}

AppState::UpdateSignal AppState::signal_bandwidth_changed() {
    return m_sig_bandwidth;
}

void AppState::emit_on_main(UpdateSignal& sig) {
    Glib::signal_idle().connect_once([&sig]() {
        sig.emit();
    });
}
