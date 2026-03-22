#pragma once

#include <gtkmm.h>
#include "ui/general_tab.hpp"
#include "ui/firewall_tab.hpp"
#include "ui/hotspot_tab.hpp"
#include "ui/pxe_tab.hpp"
#include "ui/bridge_tab.hpp"
#include "ui/tools_tab.hpp"
#include "ui/mac_spoofer_tab.hpp"
#include "ui/log_panel.hpp"

class MainWindow : public Gtk::ApplicationWindow {
public:
    MainWindow();
    virtual ~MainWindow() = default;

private:
    void setup_ui();
    void on_log_toggle();

    // Main layout
    Gtk::Box m_main_box{Gtk::Orientation::VERTICAL};
    Gtk::Paned m_content_paned{Gtk::Orientation::HORIZONTAL};  // Tabs ↔ Log
    
    // Header with tabs
    Gtk::Notebook m_notebook;
    Gtk::ToggleButton m_log_button{"📜 Log"};
    
    // Tabs
    GeneralTab m_general_tab;
    FirewallTab m_firewall_tab;
    HotspotTab m_hotspot_tab;
    PXETab m_pxe_tab;
    BridgeTab m_bridge_tab;
    ToolsTab m_tools_tab;
    MACSpoofTab m_mac_spoof_tab;
    
    // Log panel (right side, toggleable)
    LogPanel m_log_panel;
    bool m_log_visible{false};
};

class NetManApp : public Gtk::Application {
public:
    static Glib::RefPtr<NetManApp> create();

protected:
    NetManApp();
    void on_activate() override;

private:
    MainWindow* m_window{nullptr};
};
