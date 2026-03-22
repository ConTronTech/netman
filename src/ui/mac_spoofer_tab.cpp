#include "mac_spoofer_tab.hpp"
#include "../core/state.hpp"

MACSpoofTab::MACSpoofTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
    
    // Initial refresh
    on_interface_changed();
    
    // Timer for status updates
    m_timer = Glib::signal_timeout().connect(
        sigc::bind_return(sigc::mem_fun(*this, &MACSpoofTab::refresh_status), true),
        2000);
}

MACSpoofTab::~MACSpoofTab() {
    m_timer.disconnect();
    mac_spoofer::stop_monitor();
}

void MACSpoofTab::setup_ui() {
    // === Interface Section ===
    m_iface_grid.set_margin(10);
    m_iface_grid.set_row_spacing(8);
    m_iface_grid.set_column_spacing(15);
    
    // Populate interface dropdown
    auto ifaces = interfaces::list();
    for (const auto& iface : ifaces) {
        m_iface_combo.append(iface.name);
    }
    if (!ifaces.empty()) {
        m_iface_combo.set_active(0);
        m_current_iface = ifaces[0].name;
    }
    
    m_iface_combo.signal_changed().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_interface_changed));
    
    m_iface_grid.attach(m_iface_combo, 0, 0);
    m_iface_grid.attach(m_iface_type_label, 1, 0);
    m_iface_grid.attach(m_iface_status_label, 2, 0);
    
    m_iface_grid.attach(m_current_mac_label, 0, 1);
    m_iface_grid.attach(m_current_mac_value, 1, 1, 2, 1);
    
    m_iface_grid.attach(m_original_mac_label, 0, 2);
    m_iface_grid.attach(m_original_mac_value, 1, 2, 2, 1);
    
    m_current_mac_value.set_xalign(0);
    m_original_mac_value.set_xalign(0);
    m_current_mac_value.set_selectable(true);
    m_original_mac_value.set_selectable(true);
    
    m_iface_frame.set_child(m_iface_grid);
    append(m_iface_frame);

    // === Spoof Section ===
    m_spoof_grid.set_margin(10);
    m_spoof_grid.set_row_spacing(8);
    m_spoof_grid.set_column_spacing(10);
    
    m_spoof_grid.attach(*Gtk::make_managed<Gtk::Label>("New MAC:"), 0, 0);
    m_new_mac_entry.set_placeholder_text("XX:XX:XX:XX:XX:XX");
    m_new_mac_entry.set_max_length(17);
    m_spoof_grid.attach(m_new_mac_entry, 1, 0);
    m_spoof_grid.attach(m_random_btn, 2, 0);
    
    // Vendor dropdown
    m_spoof_grid.attach(*Gtk::make_managed<Gtk::Label>("Vendor:"), 0, 1);
    for (const auto& v : mac_spoofer::get_vendors()) {
        m_vendor_combo.append(v.name);
    }
    m_vendor_combo.set_active(0);
    m_vendor_combo.signal_changed().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_vendor_changed));
    m_spoof_grid.attach(m_vendor_combo, 1, 1, 2, 1);
    
    // Buttons
    auto btn_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
    m_apply_btn.add_css_class("suggested-action");
    btn_box->append(m_apply_btn);
    btn_box->append(m_restore_btn);
    m_spoof_grid.attach(*btn_box, 1, 2, 2, 1);
    
    m_random_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_random_clicked));
    m_apply_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_apply_clicked));
    m_restore_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_restore_clicked));
    
    m_spoof_frame.set_child(m_spoof_grid);
    append(m_spoof_frame);

    // === Auto-Spoof Section ===
    m_auto_grid.set_margin(10);
    m_auto_grid.set_row_spacing(5);
    m_auto_grid.set_column_spacing(10);
    
    m_auto_grid.attach(m_enable_auto, 0, 0, 2, 1);
    
    auto lock_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 5);
    lock_box->append(m_lock_network);
    m_target_ssid_entry.set_placeholder_text("SSID");
    m_target_ssid_entry.set_size_request(150, -1);
    lock_box->append(m_target_ssid_entry);
    m_auto_grid.attach(*lock_box, 0, 1, 2, 1);
    
    m_auto_grid.attach(m_respoof_reconnect, 0, 2, 2, 1);
    m_auto_grid.attach(m_notifications, 0, 3, 2, 1);
    
    auto interval_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 5);
    interval_box->append(m_interval_label);
    m_interval_spin.set_range(1, 60);
    m_interval_spin.set_value(5);
    m_interval_spin.set_increments(1, 5);
    interval_box->append(m_interval_spin);
    m_auto_grid.attach(*interval_box, 0, 4, 2, 1);
    
    auto monitor_btn_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
    m_start_monitor_btn.add_css_class("suggested-action");
    m_stop_monitor_btn.add_css_class("destructive-action");
    m_stop_monitor_btn.set_sensitive(false);
    monitor_btn_box->append(m_start_monitor_btn);
    monitor_btn_box->append(m_stop_monitor_btn);
    m_auto_grid.attach(*monitor_btn_box, 0, 5, 2, 1);
    
    m_start_monitor_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_start_monitor_clicked));
    m_stop_monitor_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &MACSpoofTab::on_stop_monitor_clicked));
    
    // Set defaults
    m_respoof_reconnect.set_active(true);
    m_notifications.set_active(true);
    
    m_auto_frame.set_child(m_auto_grid);
    append(m_auto_frame);

    // === Status Section ===
    m_status_grid.set_margin(10);
    m_status_grid.set_row_spacing(5);
    m_status_grid.set_column_spacing(15);
    
    m_status_grid.attach(m_internet_label, 0, 0);
    m_status_grid.attach(m_internet_value, 1, 0);
    m_status_grid.attach(m_monitor_status_label, 0, 1);
    m_status_grid.attach(m_monitor_status_value, 1, 1);
    m_status_grid.attach(m_last_spoof_label, 0, 2);
    m_status_grid.attach(m_last_spoof_value, 1, 2);
    
    m_internet_value.set_xalign(0);
    m_monitor_status_value.set_xalign(0);
    m_last_spoof_value.set_xalign(0);
    
    m_status_frame.set_child(m_status_grid);
    append(m_status_frame);

    // === History Section ===
    m_history_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_history_scroll.set_min_content_height(100);
    m_history_scroll.set_expand(true);
    
    m_history_list.set_selection_mode(Gtk::SelectionMode::NONE);
    m_history_list.set_placeholder(*Gtk::make_managed<Gtk::Label>("No spoof history"));
    
    m_history_scroll.set_child(m_history_list);
    m_history_frame.set_child(m_history_scroll);
    append(m_history_frame);
}

void MACSpoofTab::on_interface_changed() {
    m_current_iface = m_iface_combo.get_active_text();
    if (m_current_iface.empty()) return;
    
    refresh_interface_info();
    
    // Pre-fill target SSID with current
    std::string ssid = mac_spoofer::get_ssid(m_current_iface);
    if (ssid != "Not Connected") {
        m_target_ssid_entry.set_text(ssid);
    }
}

void MACSpoofTab::refresh_interface_info() {
    if (m_current_iface.empty()) return;
    
    // Store original on first access
    mac_spoofer::store_original_mac(m_current_iface);
    
    // Get interface info
    auto iface = interfaces::get(m_current_iface);
    
    // Type
    if (m_current_iface.find("wl") == 0 || m_current_iface.find("wifi") == 0) {
        m_iface_type_label.set_text("WiFi");
    } else {
        m_iface_type_label.set_text("Ethernet");
    }
    
    // Status
    std::string status = iface.state;
    if (mac_spoofer::is_wifi_connected(m_current_iface)) {
        status += " - " + mac_spoofer::get_ssid(m_current_iface);
    }
    m_iface_status_label.set_text(status);
    
    // MACs
    m_current_mac_value.set_text(mac_spoofer::get_current_mac(m_current_iface));
    m_original_mac_value.set_text(mac_spoofer::get_original_mac(m_current_iface));
}

void MACSpoofTab::on_random_clicked() {
    m_new_mac_entry.set_text(mac_spoofer::generate_random_mac());
}

void MACSpoofTab::on_vendor_changed() {
    std::string vendor = m_vendor_combo.get_active_text();
    if (vendor == "Random") {
        m_new_mac_entry.set_text(mac_spoofer::generate_random_mac());
    } else {
        m_new_mac_entry.set_text(mac_spoofer::generate_vendor_mac(vendor));
    }
}

void MACSpoofTab::on_apply_clicked() {
    std::string new_mac = m_new_mac_entry.get_text();
    
    if (!mac_spoofer::is_valid_mac(new_mac)) {
        m_current_mac_value.set_text("Invalid MAC format!");
        return;
    }
    
    if (mac_spoofer::apply_mac(m_current_iface, new_mac)) {
        refresh_interface_info();
        refresh_history();
    } else {
        m_current_mac_value.set_text("Failed to apply MAC");
    }
}

void MACSpoofTab::on_restore_clicked() {
    if (mac_spoofer::restore_original(m_current_iface)) {
        refresh_interface_info();
        refresh_history();
    }
}

void MACSpoofTab::on_start_monitor_clicked() {
    int interval = m_interval_spin.get_value_as_int();
    bool lock = m_lock_network.get_active();
    std::string ssid = m_target_ssid_entry.get_text();
    bool notif = m_notifications.get_active();
    
    mac_spoofer::start_monitor(m_current_iface, interval, lock, ssid, notif,
        [this](const mac_spoofer::SpoofEvent& event) {
            // Called from background thread - need to dispatch to main
            Glib::signal_idle().connect_once([this, event]() {
                on_spoof_event(event);
            });
        });
    
    m_start_monitor_btn.set_sensitive(false);
    m_stop_monitor_btn.set_sensitive(true);
    m_monitor_status_value.set_text("Running");
}

void MACSpoofTab::on_stop_monitor_clicked() {
    mac_spoofer::stop_monitor();
    m_start_monitor_btn.set_sensitive(true);
    m_stop_monitor_btn.set_sensitive(false);
    m_monitor_status_value.set_text("Stopped");
}

void MACSpoofTab::on_spoof_event(const mac_spoofer::SpoofEvent& event) {
    refresh_interface_info();
    refresh_history();
    m_last_spoof_value.set_text(event.timestamp + " → " + event.new_mac);
}

void MACSpoofTab::refresh_history() {
    // Clear
    auto child = m_history_list.get_first_child();
    while (child) {
        auto next = child->get_next_sibling();
        m_history_list.remove(*child);
        child = next;
    }
    
    auto history = mac_spoofer::get_history();
    for (const auto& event : history) {
        std::string text = event.timestamp + "  " + 
                          event.old_mac.substr(0, 8) + "... → " +
                          event.new_mac.substr(0, 8) + "...  " +
                          event.interface;
        if (!event.ssid.empty() && event.ssid != "Not Connected") {
            text += "  (" + event.ssid + ")";
        }
        
        auto label = Gtk::make_managed<Gtk::Label>(text);
        label->set_xalign(0);
        label->set_margin(3);
        m_history_list.append(*label);
    }
}

void MACSpoofTab::refresh_status() {
    // Monitor status (fast, local)
    m_monitor_status_value.set_text(mac_spoofer::is_monitoring() ? "Running" : "Stopped");
    
    // Refresh MAC display (fast, file read)
    if (!m_current_iface.empty()) {
        m_current_mac_value.set_text(mac_spoofer::get_current_mac(m_current_iface));
    }
    
    // Internet status from STATE cache (instant)
    if (STATE.has_internet()) {
        if (STATE.is_captive_portal()) {
            m_internet_value.set_text("⚠ Captive Portal");
        } else {
            m_internet_value.set_text("✓ Connected");
        }
    } else {
        m_internet_value.set_text("✗ No Connection");
    }
}
