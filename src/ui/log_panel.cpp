#include "log_panel.hpp"

LogPanel::LogPanel() : Gtk::Box(Gtk::Orientation::VERTICAL) {
    setup_ui();
}

LogPanel::~LogPanel() {
    // VTE terminal cleanup handled by GTK
}

void LogPanel::setup_ui() {
    set_margin(5);
    
    // === Controls ===
    m_controls_box.set_margin(5);
    m_controls_box.append(m_filter_combo);
    m_controls_box.append(m_clear_btn);
    
    m_clear_btn.signal_clicked().connect(
        sigc::mem_fun(*this, &LogPanel::clear));
    
    m_inner_box.append(m_controls_box);

    // === VTE Terminal ===
    m_terminal = vte_terminal_new();
    
    if (m_terminal) {
        // Configure terminal
        vte_terminal_set_scrollback_lines(VTE_TERMINAL(m_terminal), 10000);
        vte_terminal_set_scroll_on_output(VTE_TERMINAL(m_terminal), TRUE);
        
        // Set font
        PangoFontDescription* font = pango_font_description_from_string("Monospace 9");
        vte_terminal_set_font(VTE_TERMINAL(m_terminal), font);
        pango_font_description_free(font);
        
        // Wrap GTK C widget for gtkmm
        m_terminal_widget = Glib::wrap(m_terminal);
        m_terminal_widget->set_expand(true);
        
        m_scroll.set_child(*m_terminal_widget);
        m_scroll.set_expand(true);
        m_scroll.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);
        
        m_inner_box.append(m_scroll);
        
        // Show welcome message
        append_log("NetMan Log Started\n");
        append_log("==================\n\n");
    } else {
        // Fallback if VTE fails
        auto fallback = Gtk::make_managed<Gtk::Label>("VTE terminal failed to initialize");
        fallback->set_expand(true);
        m_inner_box.append(*fallback);
    }
    
    m_frame.set_child(m_inner_box);
    m_frame.set_expand(true);
    append(m_frame);
}

void LogPanel::append_log(const std::string& message) {
    if (m_terminal) {
        vte_terminal_feed(VTE_TERMINAL(m_terminal), 
                          message.c_str(), 
                          message.length());
    }
}

void LogPanel::clear() {
    if (m_terminal) {
        vte_terminal_reset(VTE_TERMINAL(m_terminal), TRUE, TRUE);
        append_log("Log cleared.\n\n");
    }
}
