#pragma once

#include <gtkmm.h>
#include "../net/interfaces.hpp"
#include "../net/scanner.hpp"
#include "../net/iptables.hpp"
#include <vector>
#include <map>

class GeneralTab : public Gtk::Box {
public:
    GeneralTab();
    virtual ~GeneralTab() = default;

private:
    void setup_ui();
    void refresh_interfaces();
    void refresh_bandwidth();
    void refresh_devices();
    void on_scan_clicked();
    void on_restart_clicked();
    void on_random_mac_clicked();
    
    // Format bytes to human readable
    std::string format_bytes(uint64_t bytes);
    std::string format_speed(uint64_t bytes_diff);
    
    // Signal connections
    sigc::connection m_conn_interfaces;
    sigc::connection m_conn_bandwidth;
    sigc::connection m_conn_devices;

    // Paned containers for resizable sections (chained vertically)
    Gtk::Paned m_paned1{Gtk::Orientation::VERTICAL};  // Status ↔ rest
    Gtk::Paned m_paned2{Gtk::Orientation::VERTICAL};  // Interfaces ↔ rest
    Gtk::Paned m_paned3{Gtk::Orientation::VERTICAL};  // Actions ↔ Devices

    // Status section
    Gtk::Frame m_status_frame{"Status"};
    Gtk::Grid m_status_grid;
    Gtk::Label m_iface_label{"Interface:"};
    Gtk::Label m_iface_value{""};
    Gtk::Label m_ip_label{"IP:"};
    Gtk::Label m_ip_value{""};
    Gtk::Label m_gateway_label{"Gateway:"};
    Gtk::Label m_gateway_value{""};
    Gtk::Label m_dns_label{"DNS:"};
    Gtk::Label m_dns_value{""};
    Gtk::Label m_down_label{"▼"};
    Gtk::Label m_down_value{"0 B/s"};
    Gtk::Label m_up_label{"▲"};
    Gtk::Label m_up_value{"0 B/s"};

    // Interfaces section
    Gtk::Frame m_iface_frame{"Interfaces"};
    Gtk::ScrolledWindow m_iface_scroll;
    Gtk::ListBox m_iface_list;

    // Quick actions section
    Gtk::Frame m_actions_frame{"Quick Actions"};
    Gtk::Box m_actions_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_restart_btn{"🔄 Restart Network"};
    Gtk::Button m_random_mac_btn{"🎲 Random MAC"};
    Gtk::Button m_scan_btn{"📡 Scan Devices"};

    // Devices section
    Gtk::Frame m_devices_frame{"Devices (0)"};
    Gtk::ScrolledWindow m_devices_scroll;
    Gtk::ListBox m_devices_list;
};
