#include "bridge_tab.hpp"

BridgeTab::BridgeTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
}

void BridgeTab::setup_ui() {
    // === Config Section ===
    m_config_grid.set_margin(10);
    m_config_grid.set_row_spacing(10);
    m_config_grid.set_column_spacing(10);
    
    // Bridge name
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Bridge Name:"), 0, 0);
    m_name_entry.set_text("br0");
    m_config_grid.attach(m_name_entry, 1, 0);
    
    // Interfaces
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Interfaces:"), 0, 1);
    auto iface_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
    iface_box->append(m_eth_check);
    iface_box->append(m_wlan_check);
    m_config_grid.attach(*iface_box, 1, 1);
    
    // IP
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Bridge IP:"), 0, 2);
    m_ip_entry.set_placeholder_text("192.168.1.50/24 or DHCP");
    m_config_grid.attach(m_ip_entry, 1, 2);
    
    m_config_frame.set_child(m_config_grid);
    append(m_config_frame);

    // === Controls ===
    m_control_box.set_margin(10);
    m_create_btn.add_css_class("suggested-action");
    m_destroy_btn.add_css_class("destructive-action");
    m_destroy_btn.set_sensitive(false);
    
    m_control_box.append(m_create_btn);
    m_control_box.append(m_destroy_btn);
    m_control_box.append(m_status_label);
    append(m_control_box);

    // Spacer
    auto spacer = Gtk::make_managed<Gtk::Box>();
    spacer->set_expand(true);
    append(*spacer);
}
