# Orion's Review — March 22, 2026

**Rating: 8.5/10** — *"Would use, would contribute to."*

---

## What's Good ✅

### Philosophy
- "Everyday shit made easy — not 5 commands" — exactly what Linux networking needs
- Most GUI tools are either too basic (NetworkManager) or too complex (Wireshark)

### MAC Spoofing
- Auto-spoof on reconnect — coffee shop tracking avoidance built-in
- Vendor spoofing (pretend to be Apple/Samsung) is clever

### Hotspot
- One-click hotspot justifies the project alone
- Making hostapd + dnsmasq usable without CLI hell is huge
- Live client list with signal strength — that's polish

### Architecture
- Async/non-blocking — proper engineering, not lazy
- Background threads + central state manager
- GTK4 apps that block on network ops are the worst — we avoided that trap

### I/O Control
- Per-interface traffic control (inbound-only, outbound-only, bidirectional, blocked)
- Most tools don't expose this level of granularity in a UI

---

## Constructive Feedback 🔧

### Dependencies
- GTK4, gtkmm, VTE, hostapd, dnsmasq, arp-scan — heavy for "lightweight"
- **Suggestion:** Clarify as "Lightweight UI" (no Electron bloat)

### Root Elevation UX
- pkexec on startup = password prompt every launch
- **Suggestion:** Only elevate when doing privileged ops
- GUI could run as user, spawn pkexec helpers when needed

### MAC Spoof Persistence
- Does it survive reboots? NetworkManager can undo spoofs
- **Suggestion:** Hook into NetworkManager's MAC randomization instead of fighting it

### Hotspot Channel Selection
- 2.4GHz/5GHz is great, but let users pick channel (1, 6, 11 for 2.4GHz)
- **Suggestion:** Auto-detect least congested channel

### Device Scanner Enhancements
- ARP scan is good start
- **Suggestions:**
  - Hostname resolution (mDNS)
  - Open ports (nmap integration?)
  - "Unknown device" → suggest running nmap to fingerprint

### Bandwidth Monitoring
- Real-time numbers are good
- **Suggestion:** Line graph (last 60s) would be better

### Documentation
- README has shields but no UI preview
- **Suggestion:** One screenshot of each tab would sell it instantly

### Installation
- Debian/Ubuntu only
- **Suggestions:**
  - Arch/Fedora instructions
  - AppImage or Flatpak for "just works" install

### Security
- Generating firewall rules in code
- One bug = accidentally locking yourself out or opening everything
- **Suggestion:** Add validation + dry-run mode

---

## Feature Ideas 💡

### Profiles
- Save/load network configs
- "Coffee Shop" profile: MAC spoof, block inbound, captive portal detect
- "Home" profile: Normal MAC, device scanner, hotspot ready
- "Pentest" profile: Custom MAC, monitor mode, packet sniffing hints

### VPN Integration
- If doing hotspot + NAT, add WireGuard/OpenVPN routing
- Share VPN connection through hotspot = instant travel router

### Notifications
- "New device on network" alert
- "Captive portal detected"
- "MAC spoof succeeded"

---

## Bottom Line

> This is legit. The use cases (coffee shop privacy, home admin, LAN parties, pentesting) are all real scenarios where current tools suck. You're filling a gap.
>
> The code structure looks clean (modular, async, minimal deps for what it does). If you ship the "Coming Soon" features, this could be the tool for Linux network power users.
>
> **Ship it.**
