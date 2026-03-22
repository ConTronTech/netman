#pragma once

#include <gtkmm.h>
#include <vte/vte.h>

class LogPanel : public Gtk::Box {
public:
    LogPanel();
    virtual ~LogPanel();

    void append_log(const std::string& message);
    void clear();

private:
    void setup_ui();

    Gtk::Frame m_frame{"Log"};
    Gtk::Box m_inner_box{Gtk::Orientation::VERTICAL, 5};
    
    // Filter/controls
    Gtk::Box m_controls_box{Gtk::Orientation::HORIZONTAL, 5};
    Gtk::DropDown m_filter_combo;
    Gtk::Button m_clear_btn{"Clear"};
    
    // VTE Terminal widget
    GtkWidget* m_terminal{nullptr};
    Gtk::Widget* m_terminal_widget{nullptr};
    Gtk::ScrolledWindow m_scroll;
};
