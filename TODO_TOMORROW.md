# NetMan - Progress Log

**Last Updated:** Sunday, March 22, 2026 — 5:19 AM

---

## ✅ COMPLETED

### Session 1: Foundation (4:00 AM - 5:19 AM)

**Infrastructure:**
- [x] `helpers/exec` — command execution wrapper
- [x] `helpers/async` — async helper for non-blocking UI
- [x] `core/state` — central state manager (cache + background refresh)
- [x] Auto-elevate to root via pkexec on startup
- [x] Resizable panes (Gtk::Paned) — 3 vertical + 1 horizontal for log

**General Tab:**
- [x] Real interface display (name, state, IP, MAC, signal)
- [x] Live bandwidth monitoring (rx/tx speed)
- [x] Hot-plug detection (new interfaces auto-appear)
- [x] Device scanner (ARP scan, async)
- [x] I/O control dropdown per interface (iptables, async)

**MAC Spoofer Tab (NEW):**
- [x] Interface selector + type/status display
- [x] Current + original MAC tracking
- [x] Random MAC generation
- [x] Vendor MAC presets (Apple, Samsung, Intel, etc.)
- [x] Apply / Restore buttons
- [x] Auto-spoof mode:
  - [x] Lock to specific network (SSID)
  - [x] Re-spoof on reconnect
  - [x] Configurable interval
  - [x] Desktop notifications option
- [x] Internet status (captive portal detection)
- [x] Spoof history

**Performance:**
- [x] STATE manager — background thread refreshes, UI reads from cache
- [x] Signal-based updates — UI subscribes, reacts to changes
- [x] Async I/O control — no UI freeze on iptables calls
- [x] Async device scan — non-blocking

---

## 🔲 TODO (Next Session)

### Priority 1: Next Up

| Feature | Tab | Status | Notes |
|---------|-----|--------|-------|
| **Hotspot** | Hotspot | NEXT | hostapd + dnsmasq, one-click AP |
| **Firewall Builder** | Firewall | NEXT | Rule builder UI, presets |

### Priority 2: After That

| Feature | Tab | Status | Notes |
|---------|-----|--------|-------|
| PXE Server | PXE | TODO | dnsmasq tftp, boot image select |

### Priority 2: Tab Completion

| Feature | Tab | Status | Notes |
|---------|-----|--------|-------|
| Bridge | Bridge | TODO | Create/destroy bridge |
| Bandwidth Throttle | Tools | TODO | tc qdisc wrapper |
| Log Panel | Log | TODO | Capture command output |

### Priority 3: Polish

- [ ] Config persistence (save/load profiles)
- [ ] Error handling / user feedback toasts
- [ ] Keyboard shortcuts
- [ ] Theme/styling

---

## Architecture Summary

```
src/
├── main.cpp              # Entry + root elevation
├── app.cpp               # Main window, tabs
├── core/
│   └── state.cpp         # Central state manager
├── helpers/
│   ├── exec.cpp          # Command execution
│   └── async.hpp         # Async helper
├── net/
│   ├── interfaces.cpp    # NIC enumeration
│   ├── scanner.cpp       # ARP scan
│   ├── iptables.cpp      # Firewall rules
│   └── mac_spoofer.cpp   # MAC spoofing
└── ui/
    ├── general_tab.cpp
    ├── mac_spoofer_tab.cpp
    ├── firewall_tab.cpp  # (stub)
    ├── hotspot_tab.cpp   # (stub)
    ├── pxe_tab.cpp       # (stub)
    ├── bridge_tab.cpp    # (stub)
    ├── tools_tab.cpp     # (stub)
    └── log_panel.cpp
```

---

## Build & Run

```bash
# Dependencies
sudo apt install build-essential libgtkmm-4.0-dev libvte-2.91-gtk4-dev

# Build
make clean && make

# Run (auto-elevates to root)
./netman
```
