#pragma once

#include <gtkmm.h>

class ToolsTab : public Gtk::Box {
public:
    ToolsTab();
    virtual ~ToolsTab() = default;

private:
    void setup_ui();

    // MAC Spoofer
    Gtk::Frame m_mac_frame{"MAC Spoofer"};
    Gtk::Grid m_mac_grid;
    Gtk::DropDown m_mac_iface_combo;
    Gtk::Label m_current_mac{"Current: --:--:--:--:--:--"};
    Gtk::Entry m_new_mac_entry;
    Gtk::Button m_random_mac_btn{"Random"};
    Gtk::Button m_apply_mac_btn{"Apply"};
    Gtk::Button m_restore_mac_btn{"Restore"};

    // Bandwidth throttle
    Gtk::Frame m_bw_frame{"Bandwidth Control"};
    Gtk::Grid m_bw_grid;
    Gtk::Scale m_down_scale{Gtk::Orientation::HORIZONTAL};
    Gtk::Scale m_up_scale{Gtk::Orientation::HORIZONTAL};
    Gtk::Button m_apply_bw_btn{"Apply Limits"};
    Gtk::Button m_clear_bw_btn{"Clear"};

    // Helpers
    Gtk::Frame m_helpers_frame{"External Tools"};
    Gtk::Box m_helpers_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_nmap_btn{"Launch nmap"};
    Gtk::Button m_wireshark_btn{"Launch Wireshark"};
    Gtk::Button m_tcpdump_btn{"Quick tcpdump"};
};
