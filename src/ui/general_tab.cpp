#include "general_tab.hpp"
#include "../net/interfaces.hpp"
#include "../core/state.hpp"
#include <thread>

GeneralTab::GeneralTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
    
    // Connect to state signals
    m_conn_interfaces = STATE.signal_interfaces_changed().connect(
        sigc::mem_fun(*this, &GeneralTab::refresh_interfaces));
    m_conn_bandwidth = STATE.signal_bandwidth_changed().connect(
        sigc::mem_fun(*this, &GeneralTab::refresh_bandwidth));
    m_conn_devices = STATE.signal_devices_changed().connect(
        sigc::mem_fun(*this, &GeneralTab::refresh_devices));
    
    // Initial load from cache
    refresh_interfaces();
    refresh_bandwidth();
}

std::string GeneralTab::format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f %s", size, units[unit]);
    return buf;
}

std::string GeneralTab::format_speed(uint64_t bytes_diff) {
    return format_bytes(bytes_diff) + "/s";
}

void GeneralTab::setup_ui() {
    // === Status Section ===
    m_status_grid.set_margin(10);
    m_status_grid.set_row_spacing(5);
    m_status_grid.set_column_spacing(20);
    
    m_status_grid.attach(m_iface_label, 0, 0);
    m_status_grid.attach(m_iface_value, 1, 0);
    m_status_grid.attach(m_ip_label, 2, 0);
    m_status_grid.attach(m_ip_value, 3, 0);
    
    m_status_grid.attach(m_gateway_label, 0, 1);
    m_status_grid.attach(m_gateway_value, 1, 1);
    m_status_grid.attach(m_dns_label, 2, 1);
    m_status_grid.attach(m_dns_value, 3, 1);
    
    m_status_grid.attach(m_down_label, 0, 2);
    m_status_grid.attach(m_down_value, 1, 2);
    m_status_grid.attach(m_up_label, 2, 2);
    m_status_grid.attach(m_up_value, 3, 2);
    
    // Style labels
    m_iface_label.set_xalign(0);
    m_ip_label.set_xalign(0);
    m_gateway_label.set_xalign(0);
    m_dns_label.set_xalign(0);
    m_iface_value.set_xalign(0);
    m_ip_value.set_xalign(0);
    m_gateway_value.set_xalign(0);
    m_dns_value.set_xalign(0);
    
    m_status_frame.set_child(m_status_grid);

    // === Interfaces Section ===
    m_iface_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_iface_scroll.set_min_content_height(80);
    m_iface_list.set_selection_mode(Gtk::SelectionMode::NONE);
    
    m_iface_scroll.set_child(m_iface_list);
    m_iface_frame.set_child(m_iface_scroll);

    // === Quick Actions Section ===
    m_actions_box.set_margin(10);
    m_actions_box.set_halign(Gtk::Align::START);
    
    m_restart_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &GeneralTab::on_restart_clicked));
    m_random_mac_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &GeneralTab::on_random_mac_clicked));
    m_scan_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &GeneralTab::on_scan_clicked));
    
    m_actions_box.append(m_restart_btn);
    m_actions_box.append(m_random_mac_btn);
    m_actions_box.append(m_scan_btn);
    
    m_actions_frame.set_child(m_actions_box);

    // === Devices Section ===
    m_devices_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_devices_scroll.set_expand(true);
    
    m_devices_list.set_selection_mode(Gtk::SelectionMode::SINGLE);
    m_devices_list.set_placeholder(*Gtk::make_managed<Gtk::Label>("Click 'Scan Devices' to discover"));
    
    m_devices_scroll.set_child(m_devices_list);
    m_devices_frame.set_child(m_devices_scroll);

    // === Build resizable layout with chained Panes ===
    // Structure: Status ↔ (Interfaces ↔ (Actions ↔ Devices))
    
    // Pane 3: Actions ↔ Devices (bottom two)
    m_paned3.set_start_child(m_actions_frame);
    m_paned3.set_end_child(m_devices_frame);
    m_paned3.set_shrink_start_child(false);
    m_paned3.set_shrink_end_child(false);
    m_paned3.set_resize_start_child(false);  // Actions stays compact
    m_paned3.set_resize_end_child(true);     // Devices expands
    
    // Pane 2: Interfaces ↔ (Actions + Devices)
    m_paned2.set_start_child(m_iface_frame);
    m_paned2.set_end_child(m_paned3);
    m_paned2.set_shrink_start_child(false);
    m_paned2.set_shrink_end_child(false);
    m_paned2.set_resize_start_child(true);
    m_paned2.set_resize_end_child(true);
    
    // Pane 1: Status ↔ (Interfaces + Actions + Devices)
    m_paned1.set_start_child(m_status_frame);
    m_paned1.set_end_child(m_paned2);
    m_paned1.set_shrink_start_child(false);
    m_paned1.set_shrink_end_child(false);
    m_paned1.set_resize_start_child(false);  // Status stays compact
    m_paned1.set_resize_end_child(true);
    
    m_paned1.set_expand(true);
    append(m_paned1);
}

void GeneralTab::refresh_interfaces() {
    // Clear existing - gtkmm4 compatible
    auto child = m_iface_list.get_first_child();
    while (child) {
        auto next = child->get_next_sibling();
        m_iface_list.remove(*child);
        child = next;
    }
    
    // Get from cache (instant)
    auto ifaces = STATE.get_interfaces();
    
    // Find first connected interface for status panel
    for (const auto& iface : ifaces) {
        if (!iface.ip.empty()) {
            m_iface_value.set_text(iface.name + " (" + iface.state + ")");
            m_ip_value.set_text(iface.ip);
            break;
        }
    }
    
    // Gateway and DNS from cache
    m_gateway_value.set_text(STATE.get_gateway());
    m_dns_value.set_text(STATE.get_dns());
    
    // Build interface list
    for (const auto& iface : ifaces) {
        auto row = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 15);
        row->set_margin(5);
        
        // Name
        auto name_label = Gtk::make_managed<Gtk::Label>(iface.name);
        name_label->set_xalign(0);
        name_label->set_size_request(80, -1);
        row->append(*name_label);
        
        // State
        auto state_label = Gtk::make_managed<Gtk::Label>(iface.state);
        state_label->set_xalign(0);
        state_label->set_size_request(60, -1);
        if (iface.state == "UP") {
            state_label->add_css_class("success");
        }
        row->append(*state_label);
        
        // IP
        auto ip_label = Gtk::make_managed<Gtk::Label>(iface.ip.empty() ? "--" : iface.ip);
        ip_label->set_xalign(0);
        ip_label->set_size_request(120, -1);
        row->append(*ip_label);
        
        // MAC
        auto mac_label = Gtk::make_managed<Gtk::Label>(iface.mac);
        mac_label->set_xalign(0);
        mac_label->set_size_request(140, -1);
        row->append(*mac_label);
        
        // Signal (wifi only)
        if (iface.signal >= 0) {
            std::string signal_str = std::to_string(iface.signal) + "%";
            auto signal_label = Gtk::make_managed<Gtk::Label>(signal_str);
            signal_label->set_size_request(50, -1);
            row->append(*signal_label);
        }
        
        // I/O Control dropdown
        auto io_combo = Gtk::make_managed<Gtk::ComboBoxText>();
        io_combo->append("Bidirectional");
        io_combo->append("Inbound Only");
        io_combo->append("Outbound Only");
        io_combo->append("Blocked");
        
        // Set current state
        auto current_state = iptables::get_io_state(iface.name);
        io_combo->set_active(static_cast<int>(current_state));
        
        // Connect change handler - run iptables async
        std::string iface_name = iface.name;  // capture for lambda
        io_combo->signal_changed().connect([io_combo, iface_name]() {
            int active = io_combo->get_active_row_number();
            if (active >= 0) {
                io_combo->set_sensitive(false);  // Disable while processing
                auto state = static_cast<iptables::IOState>(active);
                std::thread([io_combo, iface_name, state]() {
                    iptables::set_io_state(iface_name, state);
                    Glib::signal_idle().connect_once([io_combo]() {
                        io_combo->set_sensitive(true);  // Re-enable
                    });
                }).detach();
            }
        });
        
        row->append(*io_combo);
        
        m_iface_list.append(*row);
    }
}

void GeneralTab::refresh_bandwidth() {
    m_down_value.set_text(format_speed(STATE.get_rx_speed()));
    m_up_value.set_text(format_speed(STATE.get_tx_speed()));
}

void GeneralTab::refresh_devices() {
    // Clear existing
    auto child = m_devices_list.get_first_child();
    while (child) {
        auto next = child->get_next_sibling();
        m_devices_list.remove(*child);
        child = next;
    }
    
    auto devices = STATE.get_devices();
    
    for (const auto& dev : devices) {
        auto row = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 15);
        row->set_margin(5);
        
        auto ip_label = Gtk::make_managed<Gtk::Label>(dev.ip);
        ip_label->set_xalign(0);
        ip_label->set_size_request(120, -1);
        row->append(*ip_label);
        
        std::string host_str = dev.hostname;
        if (dev.is_self) {
            host_str = "* this machine";
        } else if (host_str.empty()) {
            host_str = "--";
        }
        auto host_label = Gtk::make_managed<Gtk::Label>(host_str);
        host_label->set_xalign(0);
        host_label->set_size_request(150, -1);
        row->append(*host_label);
        
        auto mac_label = Gtk::make_managed<Gtk::Label>(dev.mac);
        mac_label->set_xalign(0);
        row->append(*mac_label);
        
        m_devices_list.append(*row);
    }
    
    m_devices_frame.set_label("Devices (" + std::to_string(devices.size()) + ")");
    m_scan_btn.set_sensitive(true);
}

void GeneralTab::on_scan_clicked() {
    m_devices_frame.set_label("Devices (scanning...)");
    m_scan_btn.set_sensitive(false);
    
    // Clear existing devices
    auto child = m_devices_list.get_first_child();
    while (child) {
        auto next = child->get_next_sibling();
        m_devices_list.remove(*child);
        child = next;
    }
    
    // Request scan from state manager (async, will emit signal when done)
    STATE.request_device_scan();
}

void GeneralTab::on_restart_clicked() {
    // TODO: Implement network restart
}

void GeneralTab::on_random_mac_clicked() {
    // TODO: Implement MAC randomization
}
