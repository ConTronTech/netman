#pragma once

#include <gtkmm.h>

class PXETab : public Gtk::Box {
public:
    PXETab();
    virtual ~PXETab() = default;

private:
    void setup_ui();

    Gtk::Frame m_config_frame{"PXE Configuration"};
    Gtk::Grid m_config_grid;
    
    Gtk::Box m_control_box{Gtk::Orientation::HORIZONTAL, 10};
    Gtk::Button m_start_btn{"Start PXE"};
    Gtk::Button m_stop_btn{"Stop"};
    Gtk::Label m_status_label{"Status: Inactive"};

    Gtk::Frame m_clients_frame{"PXE Clients (0)"};
    Gtk::ScrolledWindow m_clients_scroll;
    Gtk::ListBox m_clients_list;
};
