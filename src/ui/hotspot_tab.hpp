#pragma once

#include <gtkmm.h>
#include "../net/hotspot.hpp"

class HotspotTab : public Gtk::Box {
public:
    HotspotTab();
    virtual ~HotspotTab();

private:
    void setup_ui();
    void refresh_interfaces();
    void refresh_status();
    void refresh_clients();
    void on_start_clicked();
    void on_stop_clicked();
    void on_band_changed();
    
    // Timer
    sigc::connection m_timer;
    
    // Track clients for change detection
    std::vector<hotspot::Client> m_last_clients;
    
    // Status section
    Gtk::Frame m_status_frame{"Status"};
    Gtk::Grid m_status_grid;
    Gtk::Label m_status_label{"Status:"};
    Gtk::Label m_status_value{"Stopped"};
    Gtk::Label m_clients_label{"Clients:"};
    Gtk::Label m_clients_value{"0"};
    
    // Config section
    Gtk::Frame m_config_frame{"Configuration"};
    Gtk::Grid m_config_grid;
    
    Gtk::Label m_iface_label{"WiFi Interface:"};
    Gtk::ComboBoxText m_iface_combo;
    
    Gtk::Label m_ssid_label{"SSID:"};
    Gtk::Entry m_ssid_entry;
    
    Gtk::Label m_pass_label{"Password:"};
    Gtk::Entry m_pass_entry;
    
    Gtk::Label m_band_label{"Band:"};
    Gtk::ComboBoxText m_band_combo;
    
    Gtk::Label m_channel_label{"Channel:"};
    Gtk::ComboBoxText m_channel_combo;
    
    Gtk::Label m_country_label{"Country:"};
    Gtk::ComboBoxText m_country_combo;
    
    Gtk::CheckButton m_hidden_check{"Hidden network"};
    
    Gtk::Label m_share_label{"Share internet from:"};
    Gtk::ComboBoxText m_share_combo;
    
    // Control buttons
    Gtk::Box m_btn_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_start_btn{"Start Hotspot"};
    Gtk::Button m_stop_btn{"Stop"};
    
    // Connected clients section
    Gtk::Frame m_clients_frame{"Connected Clients"};
    Gtk::ScrolledWindow m_clients_scroll;
    Gtk::ListBox m_clients_list;
    
    // Dependency warning
    Gtk::InfoBar m_dep_warning;
    Gtk::Label m_dep_label;
};
