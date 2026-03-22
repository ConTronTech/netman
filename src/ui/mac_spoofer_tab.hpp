#pragma once

#include <gtkmm.h>
#include "../net/mac_spoofer.hpp"
#include "../net/interfaces.hpp"

class MACSpoofTab : public Gtk::Box {
public:
    MACSpoofTab();
    virtual ~MACSpoofTab();

private:
    void setup_ui();
    void refresh_interface_info();
    void on_interface_changed();
    void on_random_clicked();
    void on_apply_clicked();
    void on_restore_clicked();
    void on_vendor_changed();
    void on_start_monitor_clicked();
    void on_stop_monitor_clicked();
    void refresh_history();
    void refresh_status();
    void on_spoof_event(const mac_spoofer::SpoofEvent& event);
    
    // Timer
    sigc::connection m_timer;
    
    // Current interface
    std::string m_current_iface;

    // Interface section
    Gtk::Frame m_iface_frame{"Interface"};
    Gtk::Grid m_iface_grid;
    Gtk::ComboBoxText m_iface_combo;
    Gtk::Label m_iface_type_label{""};
    Gtk::Label m_iface_status_label{""};
    Gtk::Label m_current_mac_label{"Current MAC:"};
    Gtk::Label m_current_mac_value{""};
    Gtk::Label m_original_mac_label{"Original MAC:"};
    Gtk::Label m_original_mac_value{""};

    // Spoof section
    Gtk::Frame m_spoof_frame{"Spoof"};
    Gtk::Grid m_spoof_grid;
    Gtk::Entry m_new_mac_entry;
    Gtk::Button m_random_btn{"Random"};
    Gtk::ComboBoxText m_vendor_combo;
    Gtk::Button m_apply_btn{"Apply"};
    Gtk::Button m_restore_btn{"Restore Original"};

    // Auto-spoof section
    Gtk::Frame m_auto_frame{"Auto-Spoof Mode"};
    Gtk::Grid m_auto_grid;
    Gtk::CheckButton m_enable_auto{"Enable auto-spoof"};
    Gtk::CheckButton m_lock_network{"Lock to network:"};
    Gtk::Entry m_target_ssid_entry;
    Gtk::CheckButton m_respoof_reconnect{"Re-spoof on reconnect"};
    Gtk::CheckButton m_notifications{"Desktop notifications"};
    Gtk::Label m_interval_label{"Interval (sec):"};
    Gtk::SpinButton m_interval_spin;
    Gtk::Button m_start_monitor_btn{"Start Monitoring"};
    Gtk::Button m_stop_monitor_btn{"Stop"};

    // Status section
    Gtk::Frame m_status_frame{"Status"};
    Gtk::Grid m_status_grid;
    Gtk::Label m_internet_label{"Internet:"};
    Gtk::Label m_internet_value{""};
    Gtk::Label m_last_spoof_label{"Last spoof:"};
    Gtk::Label m_last_spoof_value{"None"};
    Gtk::Label m_monitor_status_label{"Monitor:"};
    Gtk::Label m_monitor_status_value{"Stopped"};

    // History section
    Gtk::Frame m_history_frame{"History"};
    Gtk::ScrolledWindow m_history_scroll;
    Gtk::ListBox m_history_list;
};
