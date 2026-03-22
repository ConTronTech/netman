# NetMan

A lightweight Linux network manager GUI that simplifies complex networking tasks into one-click actions.

**Philosophy:** *"Everyday shit made easy — not 5 commands."*

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![GTK4](https://img.shields.io/badge/GTK-4.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## Why NetMan?

### Real-World Use Cases

**☕ Coffee Shop / Public WiFi**
- Spoof your MAC address to avoid tracking across sessions
- Detect captive portals automatically
- Block inbound connections while keeping outbound access

**🏠 Home Network Admin**
- See all devices on your network at a glance
- Monitor bandwidth usage in real-time
- Quickly identify unknown devices by MAC vendor

**📱 Share Your Connection**
- Turn your laptop into a WiFi hotspot in one click
- Share ethernet/VPN through WiFi to your phone
- See who's connected and their signal strength

**🔒 Privacy & Security**
- Randomize MAC on every connect (anti-tracking)
- Block all traffic to an interface instantly
- Control inbound vs outbound traffic per-interface

**🛠️ Network Troubleshooting**
- Quick overview of all interfaces and their states
- See gateway, DNS, IPs without terminal commands
- Device scanning to find IP conflicts or rogue devices

**🎮 LAN Parties / Events**
- Instant hotspot for guests
- Monitor connected clients
- Bandwidth visibility

**💼 Pentesting / Security Research**
- MAC spoofing for network testing
- Interface traffic control
- Quick network reconnaissance

---

## Features

### General Tab
- **Interface Overview** — View all network interfaces with state, IP, MAC, signal strength
- **Live Bandwidth** — Real-time upload/download speed monitoring
- **Device Scanner** — ARP scan to discover devices on your network
- **I/O Control** — Per-interface traffic control (bidirectional, inbound-only, outbound-only, blocked)

### MAC Spoofer Tab
- **Random MAC** — Generate random MAC addresses
- **Vendor Spoofing** — Spoof as Apple, Samsung, Intel, Google, and more
- **Auto-Spoof Mode** — Automatically spoof on WiFi reconnect
- **Captive Portal Detection** — Detect and handle captive portals
- **History** — Track all MAC changes

### Hotspot Tab
- **One-Click WiFi AP** — Turn your laptop into a hotspot instantly
- **2.4GHz / 5GHz** — Full band selection with country code support
- **NAT/Internet Sharing** — Share internet from any interface
- **Live Client List** — See connected devices with signal strength in real-time
- **Hidden Network** — Option to hide SSID

### Coming Soon
- Firewall rule builder
- PXE boot server
- Bridge management
- Bandwidth throttling

## Screenshots

*Coming soon*

## Installation

### Dependencies

```bash
# Debian/Ubuntu
sudo apt install build-essential libgtkmm-4.0-dev libvte-2.91-gtk4-dev

# For hotspot functionality
sudo apt install hostapd dnsmasq

# For device scanning
sudo apt install arp-scan
```

### Build

```bash
git clone https://github.com/ConTronTech/netman.git
cd netman
make
```

### Run

```bash
./netman
```

NetMan requires root privileges for network operations. It will automatically prompt for elevation via `pkexec` on startup.

## Architecture

```
src/
├── main.cpp              # Entry point + root elevation
├── app.cpp               # Main window + tab management
├── core/
│   └── state.cpp         # Central async state manager
├── helpers/
│   ├── exec.cpp          # Command execution wrapper
│   └── async.hpp         # Async helper for non-blocking UI
├── net/
│   ├── interfaces.cpp    # Network interface enumeration
│   ├── scanner.cpp       # ARP device scanning
│   ├── iptables.cpp      # Firewall/traffic control
│   ├── mac_spoofer.cpp   # MAC address spoofing
│   └── hotspot.cpp       # WiFi AP (hostapd + dnsmasq)
└── ui/
    ├── general_tab.cpp
    ├── mac_spoofer_tab.cpp
    ├── hotspot_tab.cpp
    └── ...
```

### Design Principles

- **Non-blocking UI** — All slow operations run in background threads
- **Central State Manager** — Single source of truth with signal-based updates
- **Modular** — Each feature is self-contained in its own module
- **Minimal Dependencies** — Just GTK4 and standard Linux tools

## Requirements

- Linux (tested on Debian/Ubuntu)
- GTK 4.0+
- gtkmm 4.0
- VTE (for terminal embedding)
- hostapd + dnsmasq (for hotspot)
- arp-scan (for device scanning)

## License

MIT

## Contributing

PRs welcome. Keep it simple, keep it working.
