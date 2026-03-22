#include "firewall_tab.hpp"

FirewallTab::FirewallTab() : Gtk::Box(Gtk::Orientation::VERTICAL, 10) {
    set_margin(10);
    setup_ui();
}

void FirewallTab::setup_ui() {
    // === Presets Section ===
    m_preset_box.set_margin(10);
    m_preset_box.append(m_preset_default);
    m_preset_box.append(m_preset_gaming);
    m_preset_box.append(m_preset_lockdown);
    m_preset_box.append(m_preset_open);
    
    m_preset_frame.set_child(m_preset_box);
    append(m_preset_frame);

    // === Rule Builder Section ===
    m_builder_grid.set_margin(10);
    m_builder_grid.set_row_spacing(10);
    m_builder_grid.set_column_spacing(10);
    
    // Chain
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Chain:"), 0, 0);
    auto chain_combo = Gtk::make_managed<Gtk::DropDown>();
    m_builder_grid.attach(*chain_combo, 1, 0);
    
    // Protocol
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Protocol:"), 0, 1);
    auto proto_combo = Gtk::make_managed<Gtk::DropDown>();
    m_builder_grid.attach(*proto_combo, 1, 1);
    
    // Source
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Source:"), 0, 2);
    auto src_entry = Gtk::make_managed<Gtk::Entry>();
    src_entry->set_placeholder_text("IP or CIDR (any)");
    m_builder_grid.attach(*src_entry, 1, 2);
    
    // Destination
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Destination:"), 0, 3);
    auto dst_entry = Gtk::make_managed<Gtk::Entry>();
    dst_entry->set_placeholder_text("IP or CIDR (any)");
    m_builder_grid.attach(*dst_entry, 1, 3);
    
    // Port
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Port:"), 0, 4);
    auto port_entry = Gtk::make_managed<Gtk::Entry>();
    port_entry->set_placeholder_text("e.g. 22, 80, 443");
    m_builder_grid.attach(*port_entry, 1, 4);
    
    // Action
    m_builder_grid.attach(*Gtk::make_managed<Gtk::Label>("Action:"), 0, 5);
    auto action_combo = Gtk::make_managed<Gtk::DropDown>();
    m_builder_grid.attach(*action_combo, 1, 5);
    
    // Add button
    auto add_btn = Gtk::make_managed<Gtk::Button>("Add Rule");
    add_btn->add_css_class("suggested-action");
    m_builder_grid.attach(*add_btn, 1, 6);
    
    m_builder_frame.set_child(m_builder_grid);
    append(m_builder_frame);

    // === Rules List Section ===
    m_rules_scroll.set_policy(Gtk::PolicyType::NEVER, Gtk::PolicyType::AUTOMATIC);
    m_rules_scroll.set_expand(true);
    m_rules_scroll.set_margin(10);
    
    // Placeholder rules
    auto rule1 = Gtk::make_managed<Gtk::Label>("INPUT -p tcp --dport 22 -j ACCEPT");
    rule1->set_xalign(0);
    rule1->set_margin(5);
    m_rules_list.append(*rule1);
    
    auto rule2 = Gtk::make_managed<Gtk::Label>("INPUT -p tcp --dport 80 -j ACCEPT");
    rule2->set_xalign(0);
    rule2->set_margin(5);
    m_rules_list.append(*rule2);
    
    auto rule3 = Gtk::make_managed<Gtk::Label>("INPUT -j DROP");
    rule3->set_xalign(0);
    rule3->set_margin(5);
    m_rules_list.append(*rule3);
    
    m_rules_scroll.set_child(m_rules_list);
    m_rules_frame.set_child(m_rules_scroll);
    append(m_rules_frame);
}
