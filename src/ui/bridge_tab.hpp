#pragma once

#include <gtkmm.h>

class BridgeTab : public Gtk::Box {
public:
    BridgeTab();
    virtual ~BridgeTab() = default;

private:
    void setup_ui();

    Gtk::Frame m_config_frame{"Bridge Configuration"};
    Gtk::Grid m_config_grid;
    Gtk::Entry m_name_entry;
    Gtk::CheckButton m_eth_check{"eth0"};
    Gtk::CheckButton m_wlan_check{"wlan0"};
    Gtk::Entry m_ip_entry;

    Gtk::Box m_control_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_create_btn{"Create Bridge"};
    Gtk::Button m_destroy_btn{"Destroy"};
    Gtk::Label m_status_label{"Status: No bridge"};
};
