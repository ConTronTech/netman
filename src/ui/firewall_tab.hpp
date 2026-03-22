#pragma once

#include <gtkmm.h>

class FirewallTab : public Gtk::Box {
public:
    FirewallTab();
    virtual ~FirewallTab() = default;

private:
    void setup_ui();

    // Preset selector
    Gtk::Frame m_preset_frame{"Presets"};
    Gtk::Box m_preset_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_preset_default{"Default"};
    Gtk::Button m_preset_gaming{"Gaming"};
    Gtk::Button m_preset_lockdown{"Lockdown"};
    Gtk::Button m_preset_open{"Open"};

    // Rule builder
    Gtk::Frame m_builder_frame{"Add Rule"};
    Gtk::Grid m_builder_grid;
    
    // Rules list
    Gtk::Frame m_rules_frame{"Active Rules"};
    Gtk::ScrolledWindow m_rules_scroll;
    Gtk::ListBox m_rules_list;
};
