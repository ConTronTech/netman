# MAC Spoofer Tab - Implementation Plan

**Reference:** `/root/clawd/projects/mac-spoofer-simple/spoof.cpp`

---

## Features to Port

### Core (from existing tool)
- [x] Interface discovery + type detection
- [ ] Current MAC display
- [ ] Original MAC tracking (restore capability)
- [ ] Random MAC generation
- [ ] MAC validation
- [ ] Apply MAC change
- [ ] Restore original MAC

### WiFi Awareness
- [ ] WiFi connection status
- [ ] Current SSID display
- [ ] Internet connectivity check
- [ ] Captive portal detection

### Auto-Spoof Mode
- [ ] Enable/disable toggle
- [ ] Lock to specific network (SSID)
- [ ] Re-spoof on reconnect
- [ ] Configurable interval
- [ ] Desktop notifications (libnotify)
- [ ] Start/stop monitoring

### History
- [ ] Log spoof events
- [ ] Show last N changes
- [ ] Timestamps

---

## UI Layout

```
┌─ MAC Spoofer ──────────────────────────────────────────┐
│                                                         │
│  ┌─ Interface ─────────────────────────────────────┐   │
│  │ [wlan0 ▼]  WiFi  UP  Connected: "HomeNetwork"   │   │
│  │ Current MAC: AA:BB:CC:DD:EE:FF                  │   │
│  │ Original MAC: 11:22:33:44:55:66                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ Spoof ─────────────────────────────────────────┐   │
│  │ New MAC: [________________] [Random] [Vendor ▼] │   │
│  │ [Apply]  [Restore Original]                     │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ Auto-Spoof Mode ───────────────────────────────┐   │
│  │ [x] Enable auto-spoof                           │   │
│  │ [x] Lock to network: [HomeNetwork    ]          │   │
│  │ [x] Re-spoof on reconnect                       │   │
│  │ [x] Desktop notifications                       │   │
│  │ Interval: [5] seconds                           │   │
│  │ [Start Monitoring]  [Stop]                      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ Status ────────────────────────────────────────┐   │
│  │ Internet: ✓ Connected (no captive portal)      │   │
│  │ Last spoof: 04:30 AM - wlan0 → DE:AD:BE:EF:... │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─ History ───────────────────────────────────────┐   │
│  │ 04:30 AA:BB:CC → DE:AD:BE  wlan0  HomeNetwork   │   │
│  │ 04:15 Original restored    wlan0               │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Files to Create

```
src/ui/mac_spoofer_tab.hpp
src/ui/mac_spoofer_tab.cpp
src/net/mac_spoofer.hpp      # Backend logic
src/net/mac_spoofer.cpp
```

---

## Backend Functions

```cpp
namespace mac_spoofer {
    struct SpoofEvent {
        std::string timestamp;
        std::string interface;
        std::string old_mac;
        std::string new_mac;
        std::string ssid;
    };

    // Core
    std::string get_current_mac(const std::string& iface);
    std::string get_original_mac(const std::string& iface);  // stored on first read
    std::string generate_random_mac();
    std::string generate_vendor_mac(const std::string& vendor);
    bool is_valid_mac(const std::string& mac);
    bool apply_mac(const std::string& iface, const std::string& mac);
    bool restore_original(const std::string& iface);

    // WiFi
    std::string get_ssid(const std::string& iface);
    bool is_wifi_connected(const std::string& iface);
    bool has_internet();
    bool is_captive_portal();

    // Auto-spoof
    void start_monitor(const std::string& iface, int interval_sec);
    void stop_monitor();
    bool is_monitoring();

    // History
    std::vector<SpoofEvent> get_history();
    void add_history(const SpoofEvent& event);
}
```

---

## Notes

- Reuse code from `spoof.cpp` where possible
- Store original MACs in memory (map<iface, original_mac>)
- Auto-spoof runs in background thread
- History stored in memory (optional: persist to file)
- Vendor MAC prefixes: Apple, Samsung, Intel, etc.
