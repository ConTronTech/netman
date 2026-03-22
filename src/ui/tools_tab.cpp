#include "tools_tab.hpp"

ToolsTab::ToolsTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
}

void ToolsTab::setup_ui() {
    // === MAC Spoofer Section ===
    m_mac_grid.set_margin(10);
    m_mac_grid.set_row_spacing(10);
    m_mac_grid.set_column_spacing(10);
    
    // Interface
    m_mac_grid.attach(*Gtk::make_managed<Gtk::Label>("Interface:"), 0, 0);
    m_mac_grid.attach(m_mac_iface_combo, 1, 0);
    
    // Current MAC
    m_mac_grid.attach(m_current_mac, 0, 1, 2, 1);
    
    // New MAC
    m_mac_grid.attach(*Gtk::make_managed<Gtk::Label>("New MAC:"), 0, 2);
    auto mac_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 5);
    m_new_mac_entry.set_placeholder_text("XX:XX:XX:XX:XX:XX");
    mac_box->append(m_new_mac_entry);
    mac_box->append(m_random_mac_btn);
    m_mac_grid.attach(*mac_box, 1, 2);
    
    // Buttons
    auto mac_btn_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
    m_apply_mac_btn.add_css_class("suggested-action");
    mac_btn_box->append(m_apply_mac_btn);
    mac_btn_box->append(m_restore_mac_btn);
    m_mac_grid.attach(*mac_btn_box, 1, 3);
    
    m_mac_frame.set_child(m_mac_grid);
    append(m_mac_frame);

    // === Bandwidth Section ===
    m_bw_grid.set_margin(10);
    m_bw_grid.set_row_spacing(10);
    m_bw_grid.set_column_spacing(10);
    
    // Download limit
    m_bw_grid.attach(*Gtk::make_managed<Gtk::Label>("Download:"), 0, 0);
    m_down_scale.set_range(0, 1000);
    m_down_scale.set_value(0);
    m_down_scale.set_hexpand(true);
    m_bw_grid.attach(m_down_scale, 1, 0);
    m_bw_grid.attach(*Gtk::make_managed<Gtk::Label>("Mbps"), 2, 0);
    
    // Upload limit
    m_bw_grid.attach(*Gtk::make_managed<Gtk::Label>("Upload:"), 0, 1);
    m_up_scale.set_range(0, 1000);
    m_up_scale.set_value(0);
    m_up_scale.set_hexpand(true);
    m_bw_grid.attach(m_up_scale, 1, 1);
    m_bw_grid.attach(*Gtk::make_managed<Gtk::Label>("Mbps"), 2, 1);
    
    // Buttons
    auto bw_btn_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
    m_apply_bw_btn.add_css_class("suggested-action");
    bw_btn_box->append(m_apply_bw_btn);
    bw_btn_box->append(m_clear_bw_btn);
    m_bw_grid.attach(*bw_btn_box, 1, 2);
    
    m_bw_frame.set_child(m_bw_grid);
    append(m_bw_frame);

    // === Helpers Section ===
    m_helpers_box.set_margin(10);
    m_helpers_box.append(m_nmap_btn);
    m_helpers_box.append(m_wireshark_btn);
    m_helpers_box.append(m_tcpdump_btn);
    
    m_helpers_frame.set_child(m_helpers_box);
    append(m_helpers_frame);
}
