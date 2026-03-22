#include "hotspot_tab.hpp"
#include "../net/interfaces.hpp"
#include "../core/state.hpp"
#include <thread>

HotspotTab::HotspotTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
    refresh_status();
    
    // Timer for status/client refresh (1 sec for responsive updates)
    m_timer = Glib::signal_timeout().connect(
        sigc::bind_return(sigc::mem_fun(*this, &HotspotTab::refresh_status), true),
        1000);
}

HotspotTab::~HotspotTab() {
    m_timer.disconnect();
}

void HotspotTab::setup_ui() {
    // === Dependency Warning ===
    auto missing = hotspot::get_missing_deps();
    if (!missing.empty()) {
        m_dep_warning.set_message_type(Gtk::MessageType::WARNING);
        m_dep_label.set_text("Missing: " + missing + " — Install with: sudo apt install " + missing);
        m_dep_warning.add_child(m_dep_label);
        m_dep_warning.set_revealed(true);
        append(m_dep_warning);
    }
    
    // === Status Section ===
    m_status_grid.set_margin(10);
    m_status_grid.set_row_spacing(5);
    m_status_grid.set_column_spacing(15);
    
    m_status_grid.attach(m_status_label, 0, 0);
    m_status_grid.attach(m_status_value, 1, 0);
    m_status_grid.attach(m_clients_label, 0, 1);
    m_status_grid.attach(m_clients_value, 1, 1);
    
    m_status_value.set_xalign(0);
    m_clients_value.set_xalign(0);
    
    m_status_frame.set_child(m_status_grid);
    append(m_status_frame);
    
    // === Config Section ===
    m_config_grid.set_margin(10);
    m_config_grid.set_row_spacing(8);
    m_config_grid.set_column_spacing(15);
    
    int row = 0;
    
    // Interface
    m_config_grid.attach(m_iface_label, 0, row);
    refresh_interfaces();
    m_config_grid.attach(m_iface_combo, 1, row++);
    
    // SSID
    m_config_grid.attach(m_ssid_label, 0, row);
    m_ssid_entry.set_text("NetMan-AP");
    m_ssid_entry.set_max_length(32);
    m_config_grid.attach(m_ssid_entry, 1, row++);
    
    // Password
    m_config_grid.attach(m_pass_label, 0, row);
    m_pass_entry.set_visibility(false);
    m_pass_entry.set_placeholder_text("Min 8 characters (empty = open)");
    m_config_grid.attach(m_pass_entry, 1, row++);
    
    // Band
    m_config_grid.attach(m_band_label, 0, row);
    m_band_combo.append("2.4", "2.4 GHz");
    m_band_combo.append("5", "5 GHz");
    m_band_combo.set_active(0);
    m_band_combo.signal_changed().connect(
        sigc::mem_fun(*this, &HotspotTab::on_band_changed));
    m_config_grid.attach(m_band_combo, 1, row++);
    
    // Channel
    m_config_grid.attach(m_channel_label, 0, row);
    on_band_changed();  // Populate channels
    m_config_grid.attach(m_channel_combo, 1, row++);
    
    // Country code (required for 5GHz)
    m_config_grid.attach(m_country_label, 0, row);
    m_country_combo.append("US", "US - United States");
    m_country_combo.append("CA", "CA - Canada");
    m_country_combo.append("GB", "GB - United Kingdom");
    m_country_combo.append("DE", "DE - Germany");
    m_country_combo.append("FR", "FR - France");
    m_country_combo.append("AU", "AU - Australia");
    m_country_combo.append("JP", "JP - Japan");
    m_country_combo.append("CN", "CN - China");
    m_country_combo.append("FI", "FI - Finland");
    m_country_combo.append("NL", "NL - Netherlands");
    m_country_combo.set_active(0);
    m_config_grid.attach(m_country_combo, 1, row++);
    
    // Hidden
    m_config_grid.attach(m_hidden_check, 1, row++);
    
    // Share from
    m_config_grid.attach(m_share_label, 0, row);
    m_share_combo.append("", "None (no internet)");
    auto ifaces = STATE.get_interfaces();
    for (const auto& iface : ifaces) {
        if (!iface.ip.empty() && iface.name.find("wl") != 0) {
            m_share_combo.append(iface.name, iface.name + " (" + iface.ip + ")");
        }
    }
    // Also add connected WiFi
    for (const auto& iface : ifaces) {
        if (!iface.ip.empty() && iface.name.find("wl") == 0) {
            m_share_combo.append(iface.name, iface.name + " (" + iface.ip + ")");
        }
    }
    m_share_combo.set_active(0);
    m_config_grid.attach(m_share_combo, 1, row++);
    
    m_config_frame.set_child(m_config_grid);
    append(m_config_frame);
    
    // === Control Buttons ===
    m_btn_box.set_margin(10);
    m_start_btn.add_css_class("suggested-action");
    m_stop_btn.add_css_class("destructive-action");
    m_stop_btn.set_sensitive(false);
    
    m_start_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &HotspotTab::on_start_clicked));
    m_stop_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &HotspotTab::on_stop_clicked));
    
    m_btn_box.append(m_start_btn);
    m_btn_box.append(m_stop_btn);
    append(m_btn_box);
    
    // === Connected Clients ===
    m_clients_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_clients_scroll.set_min_content_height(100);
    m_clients_scroll.set_expand(true);
    
    m_clients_list.set_selection_mode(Gtk::SelectionMode::NONE);
    m_clients_list.set_placeholder(*Gtk::make_managed<Gtk::Label>("No clients connected"));
    
    m_clients_scroll.set_child(m_clients_list);
    m_clients_frame.set_child(m_clients_scroll);
    append(m_clients_frame);
}

void HotspotTab::refresh_interfaces() {
    m_iface_combo.remove_all();
    
    auto ap_ifaces = hotspot::get_ap_capable_interfaces();
    
    if (ap_ifaces.empty()) {
        m_iface_combo.append("", "No WiFi interfaces found");
        m_iface_combo.set_active(0);
        m_start_btn.set_sensitive(false);
    } else {
        for (const auto& iface : ap_ifaces) {
            // Just show interface name, don't try to detect band support
            // Let hostapd be the judge
            m_iface_combo.append(iface, iface);
        }
        m_iface_combo.set_active(0);
    }
}

void HotspotTab::on_band_changed() {
    m_channel_combo.remove_all();
    
    std::string band = m_band_combo.get_active_id();
    
    if (band == "5") {
        // 5 GHz channels
        m_channel_combo.append("36", "36");
        m_channel_combo.append("40", "40");
        m_channel_combo.append("44", "44");
        m_channel_combo.append("48", "48");
        m_channel_combo.append("149", "149");
        m_channel_combo.append("153", "153");
        m_channel_combo.append("157", "157");
        m_channel_combo.append("161", "161");
    } else {
        // 2.4 GHz channels
        for (int i = 1; i <= 11; i++) {
            m_channel_combo.append(std::to_string(i), std::to_string(i));
        }
    }
    
    m_channel_combo.set_active(0);
}

void HotspotTab::refresh_status() {
    bool running = hotspot::is_running();
    
    if (running) {
        auto cfg = hotspot::get_current_config();
        m_status_value.set_text("Running (" + cfg.ssid + ")");
        m_status_value.add_css_class("success");
        m_start_btn.set_sensitive(false);
        m_stop_btn.set_sensitive(true);
        
        // Disable config while running
        m_iface_combo.set_sensitive(false);
        m_ssid_entry.set_sensitive(false);
        m_pass_entry.set_sensitive(false);
        m_band_combo.set_sensitive(false);
        m_channel_combo.set_sensitive(false);
        m_country_combo.set_sensitive(false);
        m_hidden_check.set_sensitive(false);
        m_share_combo.set_sensitive(false);
        
        refresh_clients();
    } else {
        m_status_value.set_text("Stopped");
        m_status_value.remove_css_class("success");
        m_start_btn.set_sensitive(true);
        m_stop_btn.set_sensitive(false);
        
        // Enable config
        m_iface_combo.set_sensitive(true);
        m_ssid_entry.set_sensitive(true);
        m_pass_entry.set_sensitive(true);
        m_band_combo.set_sensitive(true);
        m_channel_combo.set_sensitive(true);
        m_country_combo.set_sensitive(true);
        m_hidden_check.set_sensitive(true);
        m_share_combo.set_sensitive(true);
        
        m_clients_value.set_text("0");
        
        // Clear client list and tracking
        m_last_clients.clear();
        auto child = m_clients_list.get_first_child();
        while (child) {
            auto next = child->get_next_sibling();
            m_clients_list.remove(*child);
            child = next;
        }
    }
}

void HotspotTab::refresh_clients() {
    auto clients = hotspot::get_clients();
    
    // Detect new connections
    for (const auto& client : clients) {
        bool is_new = true;
        for (const auto& old : m_last_clients) {
            if (old.mac == client.mac) {
                is_new = false;
                break;
            }
        }
        if (is_new && !m_last_clients.empty()) {
            // New client connected - could add notification here
        }
    }
    
    // Detect disconnections
    for (const auto& old : m_last_clients) {
        bool still_here = false;
        for (const auto& client : clients) {
            if (client.mac == old.mac) {
                still_here = true;
                break;
            }
        }
        if (!still_here) {
            // Client disconnected - could add notification here
        }
    }
    
    // Only rebuild UI if client list changed
    bool changed = (clients.size() != m_last_clients.size());
    if (!changed) {
        for (size_t i = 0; i < clients.size(); i++) {
            if (clients[i].mac != m_last_clients[i].mac ||
                clients[i].ip != m_last_clients[i].ip) {
                changed = true;
                break;
            }
        }
    }
    
    m_last_clients = clients;
    m_clients_value.set_text(std::to_string(clients.size()));
    
    if (!changed) return;  // No UI rebuild needed
    
    // Clear
    auto child = m_clients_list.get_first_child();
    while (child) {
        auto next = child->get_next_sibling();
        m_clients_list.remove(*child);
        child = next;
    }
    
    for (const auto& client : clients) {
        auto row = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 15);
        row->set_margin(5);
        
        // Signal strength
        std::string signal_str = std::to_string(client.signal_percent) + "%";
        if (client.signal != 0) {
            signal_str += " (" + std::to_string(client.signal) + " dBm)";
        }
        auto signal_label = Gtk::make_managed<Gtk::Label>(signal_str);
        signal_label->set_xalign(0);
        signal_label->set_size_request(100, -1);
        row->append(*signal_label);
        
        // IP
        auto ip_label = Gtk::make_managed<Gtk::Label>(
            client.ip.empty() ? "assigning..." : client.ip);
        ip_label->set_xalign(0);
        ip_label->set_size_request(120, -1);
        row->append(*ip_label);
        
        // MAC
        auto mac_label = Gtk::make_managed<Gtk::Label>(client.mac);
        mac_label->set_xalign(0);
        mac_label->set_size_request(150, -1);
        row->append(*mac_label);
        
        // Hostname
        auto host_label = Gtk::make_managed<Gtk::Label>(
            client.hostname.empty() ? "--" : client.hostname);
        host_label->set_xalign(0);
        row->append(*host_label);
        
        m_clients_list.append(*row);
    }
}

void HotspotTab::on_start_clicked() {
    std::string iface = m_iface_combo.get_active_id();
    if (iface.empty()) return;
    
    std::string pass = m_pass_entry.get_text();
    if (!pass.empty() && pass.length() < 8) {
        m_status_value.set_text("Password must be 8+ chars");
        return;
    }
    
    hotspot::Config cfg;
    cfg.interface = iface;
    cfg.ssid = m_ssid_entry.get_text();
    cfg.password = pass;
    cfg.band = m_band_combo.get_active_id();
    cfg.channel = std::stoi(m_channel_combo.get_active_id());
    cfg.country_code = m_country_combo.get_active_id();
    cfg.hidden = m_hidden_check.get_active();
    cfg.share_from = m_share_combo.get_active_id();
    
    m_status_value.set_text("Starting...");
    m_start_btn.set_sensitive(false);
    
    // Run in background
    std::thread([this, cfg]() {
        bool success = hotspot::start(cfg);
        std::string error = hotspot::get_last_error();
        Glib::signal_idle().connect_once([this, success, error]() {
            if (success) {
                refresh_status();
            } else {
                m_status_value.set_text("Failed: " + (error.empty() ? "check /tmp/netman_hotspot.log" : error.substr(0, 50)));
                m_start_btn.set_sensitive(true);
            }
        });
    }).detach();
}

void HotspotTab::on_stop_clicked() {
    m_status_value.set_text("Stopping...");
    m_stop_btn.set_sensitive(false);
    
    std::thread([this]() {
        hotspot::stop();
        Glib::signal_idle().connect_once([this]() {
            refresh_status();
        });
    }).detach();
}
