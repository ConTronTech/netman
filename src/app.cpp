#include "app.hpp"
#include "core/state.hpp"

// ============================================================================
// MainWindow
// ============================================================================

MainWindow::MainWindow() {
    set_title("NetMan");
    set_default_size(1000, 700);
    
    setup_ui();
}

void MainWindow::setup_ui() {
    // Main vertical box
    set_child(m_main_box);
    
    // Header bar with log toggle
    auto header = Gtk::make_managed<Gtk::HeaderBar>();
    header->pack_end(m_log_button);
    set_titlebar(*header);
    
    m_log_button.signal_toggled().connect(
        sigc::mem_fun(*this, &MainWindow::on_log_toggle));
    
    // Add tabs to notebook
    m_notebook.append_page(m_general_tab, "General");
    m_notebook.append_page(m_mac_spoof_tab, "MAC Spoof");
    m_notebook.append_page(m_firewall_tab, "Firewall");
    m_notebook.append_page(m_hotspot_tab, "Hotspot");
    m_notebook.append_page(m_pxe_tab, "PXE");
    m_notebook.append_page(m_bridge_tab, "Bridge");
    m_notebook.append_page(m_tools_tab, "Tools");
    
    m_notebook.set_expand(true);
    
    // Content paned (notebook ↔ log panel) - horizontal resizable
    m_content_paned.set_expand(true);
    m_content_paned.set_start_child(m_notebook);
    m_content_paned.set_end_child(m_log_panel);
    m_content_paned.set_shrink_start_child(false);
    m_content_paned.set_shrink_end_child(false);
    m_content_paned.set_resize_start_child(true);
    m_content_paned.set_resize_end_child(true);
    m_content_paned.set_position(650);  // Default: most space to tabs
    
    // Log panel starts hidden
    m_log_panel.set_visible(false);
    m_log_panel.set_size_request(250, -1);  // Min width when visible
    
    m_main_box.append(m_content_paned);
}

void MainWindow::on_log_toggle() {
    m_log_visible = m_log_button.get_active();
    m_log_panel.set_visible(m_log_visible);
    
    if (m_log_visible) {
        m_log_button.set_label("📜 Log ✓");
    } else {
        m_log_button.set_label("📜 Log");
    }
}

// ============================================================================
// NetManApp
// ============================================================================

NetManApp::NetManApp() 
    : Gtk::Application("com.contolis.netman") {
}

Glib::RefPtr<NetManApp> NetManApp::create() {
    return Glib::make_refptr_for_instance<NetManApp>(new NetManApp());
}

void NetManApp::on_activate() {
    // Start global state manager
    STATE.start();
    
    if (!m_window) {
        m_window = new MainWindow();
        add_window(*m_window);
    }
    m_window->present();
}
