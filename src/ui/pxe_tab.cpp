#include "pxe_tab.hpp"

PXETab::PXETab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
}

void PXETab::setup_ui() {
    // === Config Section ===
    m_config_grid.set_margin(10);
    m_config_grid.set_row_spacing(10);
    m_config_grid.set_column_spacing(10);
    
    // Interface
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Interface:"), 0, 0);
    auto iface_combo = Gtk::make_managed<Gtk::DropDown>();
    m_config_grid.attach(*iface_combo, 1, 0);
    
    // Subnet
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Subnet:"), 0, 1);
    auto subnet_entry = Gtk::make_managed<Gtk::Entry>();
    subnet_entry->set_text("192.168.2.0/24");
    m_config_grid.attach(*subnet_entry, 1, 1);
    
    // Boot image
    m_config_grid.attach(*Gtk::make_managed<Gtk::Label>("Boot Image:"), 0, 2);
    auto image_combo = Gtk::make_managed<Gtk::DropDown>();
    m_config_grid.attach(*image_combo, 1, 2);
    
    m_config_frame.set_child(m_config_grid);
    append(m_config_frame);

    // === Controls ===
    m_control_box.set_margin(10);
    m_start_btn.add_css_class("suggested-action");
    m_stop_btn.add_css_class("destructive-action");
    m_stop_btn.set_sensitive(false);
    
    m_control_box.append(m_start_btn);
    m_control_box.append(m_stop_btn);
    m_control_box.append(m_status_label);
    append(m_control_box);

    // === Clients ===
    m_clients_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_clients_scroll.set_expand(true);
    m_clients_scroll.set_margin(10);
    
    m_clients_list.set_placeholder(*Gtk::make_managed<Gtk::Label>("No PXE boot requests"));
    
    m_clients_scroll.set_child(m_clients_list);
    m_clients_frame.set_child(m_clients_scroll);
    append(m_clients_frame);
}
