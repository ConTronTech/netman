# NetMan - Network Management Tool

> GUI-based network manager with embedded terminal. C++ / GTK4 / VTE.  
> Target: Acer Aspire 5733 (i5-560M, 8GB RAM, Linux)

### Dependencies

```bash
# Debian/Ubuntu/Mint
sudo apt install build-essential cmake \
    libgtkmm-4.0-dev libvte-2.91-gtk4-dev \
    nlohmann-json3-dev
```

---

## Core Philosophy

**"Everyday shit made easy — not 5 commands."**

Replace repetitive CLI workflows with one-click actions. Power users get embedded terminal + helper integration (nmap, wireshark) when needed.

---

## Layout

```
┌────────────────────────────────────────────────────────────────┐
│  NetMan                                              [—][□][×] │
├───────────────────────────────┬────────────────────────────────┤
│                               │                                │
│      GUI CONTROLS             │      TERMINAL / LOG OUTPUT     │
│      (Left Panel)             │      (Right Panel)             │
│                               │                                │
│  - Interface management       │  - Live command output         │
│  - I/O direction control      │  - System log tail             │
│  - Firewall rules             │  - Helper tool output          │
│  - Quick actions              │  - Manual command entry        │
│                               │                                │
└───────────────────────────────┴────────────────────────────────┘
```

---

## Feature Set

### 1. Interface Management
- [ ] List all interfaces (eth, wifi, vpn, etc.)
- [ ] Enable/disable interfaces
- [ ] Per-interface I/O control:
  - Inbound only
  - Outbound only
  - Bidirectional
  - Blocked
- [ ] Interface stats (IP, MAC, gateway, signal, TX/RX)

### 2. Firewall (iptables)
- [ ] Visual rule builder (no memorizing syntax)
- [ ] Rule presets (gaming, lockdown, default, custom)
- [ ] Quick swap between rulesets
- [ ] Import/export rules
- [ ] Per-interface chains

### 3. Quick Actions (One-Click)
> Multi-step processes → single button. This is the core value.

#### 🔥 HOTSPOT MODE (Reference Feature)
**Manual process:** 9 steps, 5 config files, 4 services
**NetMan:** One dialog, one button

```
[Create Hotspot]
├── SSID: ________
├── Password: ________  
├── Channel: [Auto ▼]
├── Internet via: [eth0 ▼]
└── [Start] [Stop]
```

**Behind the scenes:**
1. Kill conflicting services (NetworkManager on interface)
2. Set static IP on wlan (192.168.50.1/24)
3. Write + start hostapd (AP broadcast)
4. Write + start dnsmasq (DHCP for clients)
5. Enable kernel ip_forward
6. Apply iptables NAT:
   - `POSTROUTING -o eth0 -j MASQUERADE`
   - `FORWARD wlan0 → eth0 ACCEPT`
   - `FORWARD eth0 → wlan0 ESTABLISHED,RELATED`
7. Show connected clients in device list

**This is the template.** Every feature should follow this pattern:
> Complex manual process → Simple GUI → All the shit happens automatically

---

#### PXE BOOT SERVER
**Manual process:** dnsmasq config, tftp setup, pxelinux, boot images, IP config
**NetMan:** One panel, select image, go

```
[PXE Server]
├── Interface: [eth0 ▼]
├── Subnet: [192.168.2.0/24]
├── Boot Image: [TinyCore ▼] [Alpine] [Custom...]
├── [Start PXE] [Stop]
└── Status: Serving 192.168.2.1, 0 clients connected
```

**Behind the scenes:**
1. Set static IP on eth (192.168.2.1/24)
2. Write dnsmasq.conf:
   - DHCP range (192.168.2.10-100)
   - TFTP enable
   - PXE boot filename
3. Copy/symlink boot files to /srv/tftp
4. Start dnsmasq
5. Show PXE client requests in log panel

---

#### MAC SPOOFING
**Manual process:** `ip link set dev wlan0 down && ip link set dev wlan0 address XX:XX:XX:XX:XX:XX && ip link set dev wlan0 up`
**NetMan:** Dropdown, done

```
[MAC Spoofer]
├── Interface: [wlan0 ▼]
├── Current: DE:AD:BE:EF:CA:FE
├── New MAC: [____________] [Random] [Vendor ▼]
├── Presets: [Apple] [Samsung] [Intel] [Custom...]
└── [Apply] [Restore Original]
```

**Behind the scenes:**
1. Store original MAC
2. Bring interface down
3. Set new MAC
4. Bring interface up
5. Verify change
6. Option: persist across reboots

**Note:** Integrate Contolis's existing MAC Auto-Spoofer v2.0 C++ tool as backend?

---

#### NETWORK BRIDGE
**Manual process:** brctl/ip link, add interfaces, IP config, STP settings
**NetMan:** Pick interfaces, bridge 'em

```
[Network Bridge]
├── Bridge Name: [br0]
├── Interfaces: [☑ eth0] [☑ wlan0] [☐ usb0]
├── Bridge IP: [192.168.1.50/24] or [DHCP ▼]
└── [Create Bridge] [Destroy]
```

**Behind the scenes:**
1. Create bridge interface (ip link add br0 type bridge)
2. Add selected interfaces to bridge
3. Set IP or run DHCP client
4. Bring everything up

---

#### BANDWIDTH THROTTLE
**Manual process:** tc qdisc, classes, filters (absolute nightmare)
**NetMan:** Slider per interface/device

```
[Bandwidth Control]
├── Interface: [wlan0 ▼]
│   ├── Download limit: [▓▓▓▓▓░░░░░] 50 Mbps
│   └── Upload limit:   [▓▓░░░░░░░░] 10 Mbps
│
├── Per-Device (when in hotspot mode):
│   ├── 192.168.50.12 (phone)  [10 Mbps ▼]
│   ├── 192.168.50.15 (laptop) [Unlimited ▼]
│   └── 192.168.50.20 (tablet) [5 Mbps ▼]
└── [Apply] [Clear All Limits]
```

**Behind the scenes:**
1. tc qdisc add (htb or tbf)
2. tc class add for limits
3. tc filter for per-IP rules
4. Store/restore on profile switch

---

#### OUT OF SCOPE
- Port forwarding (too niche, use iptables directly if needed)
- VPN gateway mode (niche)
- Site/backend hosting features

### 4. Device Discovery
- [ ] ARP scan local network
- [ ] Device list with IP/MAC/hostname
- [ ] Right-click actions (block, scan ports, trace)

### 5. Helper Integration
- [ ] nmap — build scan command, run in terminal
- [ ] wireshark — launch with interface selected
- [ ] tcpdump — quick capture to file

### 6. Terminal Panel (Right Side)
- [ ] Embedded VTE terminal
- [ ] Log viewer mode (journalctl/dmesg tail)
- [ ] Command history
- [ ] Quick command buttons

### 7. Profiles/Presets
- [ ] Save current config as profile
- [ ] Quick switch between profiles
- [ ] Auto-apply on startup

---

## TODO: Define These

### Quick Actions — What repetitive tasks need one-click?

1. _____
2. _____
3. _____
4. _____
5. _____

### Firewall Presets — What default rulesets?

1. **Default** — ???
2. **Gaming** — ???
3. **Lockdown** — ???
4. **Open** — ???
5. Custom...

### What's OUT of scope?

- _____
- _____

---

## Tech Stack

| Component | Choice | Notes |
|-----------|--------|-------|
| Language | C++ | Faster to ship, thin GTK bindings |
| GUI | gtkmm-4.0 | C++ wrapper for GTK4 |
| Terminal | VTE | libvte for embedded terminal |
| Build | CMake or Meson | Standard C++ build |
| Config | JSON (nlohmann/json) | Profiles, settings |
| Threading | std::thread / glib | Background tasks |

---

## Architecture

```
src/
├── main.cpp             # Entry point
├── app.hpp/cpp          # Main window, state management
├── ui/
│   ├── header_bar.hpp/cpp
│   ├── general_tab.hpp/cpp
│   ├── firewall_tab.hpp/cpp
│   ├── hotspot_tab.hpp/cpp
│   ├── pxe_tab.hpp/cpp
│   ├── bridge_tab.hpp/cpp
│   ├── tools_tab.hpp/cpp
│   └── log_panel.hpp/cpp
├── net/
│   ├── interfaces.hpp/cpp    # NIC enumeration, control
│   ├── iptables.hpp/cpp      # Firewall rule management
│   ├── scanner.hpp/cpp       # ARP/device discovery
│   ├── hotspot.hpp/cpp       # hostapd/dnsmasq control
│   ├── pxe.hpp/cpp           # PXE server control
│   └── stats.hpp/cpp         # Bandwidth, connection info
├── helpers/
│   ├── exec.hpp/cpp          # Command execution wrapper
│   ├── nmap.hpp/cpp
│   └── wireshark.hpp/cpp
├── config/
│   └── config.hpp/cpp        # Profiles, persistence (JSON)
└── util/
    └── logger.hpp/cpp        # Background logging
```

---

## Open Questions

1. What "everyday shit" needs simplifying? (List specific workflows)
2. What firewall presets make sense?
3. VPN management in scope?
4. Bandwidth limiting per-interface?
5. MAC spoofing?
6. Hotspot mode?
7. Wake-on-LAN?
8. Port forwarding shortcuts?

---

## Status

**Phase: GUI Skeleton Complete**

- [x] Core concept defined
- [x] Layout defined  
- [x] Feature set locked (v1)
- [x] GUI architecture ✓
- [x] Code architecture ✓
- [x] Phase 1 scaffolding ✓
- [ ] Backend implementation
- [ ] Feature wiring

---

## Build

```bash
# Dependencies (Debian/Ubuntu/Mint)
sudo apt install build-essential libgtkmm-4.0-dev libvte-2.91-gtk4-dev

# Build
make

# Run
./netman

# Clean
make clean
```

---

## Code Architecture (Implemented)

### Current Structure
```
netman/
├── Makefile
├── build.sh
├── PLAN.md
└── src/
    ├── main.cpp              # Entry point
    ├── app.hpp/cpp           # Main window, tab container, log toggle
    └── ui/
        ├── general_tab.hpp/cpp    # Status, interfaces, I/O control, devices
        ├── firewall_tab.hpp/cpp   # Rule builder, presets, rules list
        ├── hotspot_tab.hpp/cpp    # SSID/pass config, start/stop, clients
        ├── pxe_tab.hpp/cpp        # Interface, image, start/stop, clients
        ├── bridge_tab.hpp/cpp     # Interface picker, create/destroy
        ├── tools_tab.hpp/cpp      # MAC spoof, bandwidth, helpers
        └── log_panel.hpp/cpp      # VTE terminal, log filtering
```

### Compilation Units
Each file compiles to its own `.o` — work on features independently:
```
obj/main.o
obj/app.o
obj/ui/general_tab.o
obj/ui/firewall_tab.o
obj/ui/hotspot_tab.o
obj/ui/pxe_tab.o
obj/ui/bridge_tab.o
obj/ui/tools_tab.o
obj/ui/log_panel.o
```

### Next: Backend Modules (TODO)
```
src/net/
├── interfaces.hpp/cpp    # Enumerate NICs, stats, enable/disable, I/O control
├── iptables.hpp/cpp      # Rule builder, presets, apply/save/restore
├── hotspot.hpp/cpp       # hostapd + dnsmasq management
├── pxe.hpp/cpp           # PXE server (dnsmasq + tftp)
├── scanner.hpp/cpp       # ARP scan, device discovery
└── stats.hpp/cpp         # Bandwidth monitoring (read /proc/net/dev)

src/helpers/
├── exec.hpp/cpp          # Run commands, capture stdout/stderr
└── config.hpp/cpp        # JSON profiles, settings persistence
```

### Data Flow
```
UI Tab  →  calls  →  net/ backend  →  calls  →  helpers/exec  →  system command
   ↑                      ↓
   └──── updates UI ──────┘
```

---

## Implementation Order

### Phase 2: Core Backend
1. [ ] `helpers/exec` — subprocess wrapper (popen, capture output)
2. [ ] `net/interfaces` — enumerate, stats, enable/disable
3. [ ] Wire General tab → show real interface data

### Phase 3: Firewall
4. [ ] `net/iptables` — build rules, apply, save/restore
5. [ ] Wire Firewall tab → real rule management

### Phase 4: Hotspot
6. [ ] `net/hotspot` — hostapd/dnsmasq config gen, start/stop
7. [ ] Wire Hotspot tab → one-click AP

### Phase 5: PXE
8. [ ] `net/pxe` — dnsmasq PXE config, tftp setup
9. [ ] Wire PXE tab → one-click boot server

### Phase 6: Tools
10. [ ] MAC spoofing (integrate existing C++ tool?)
11. [ ] Bandwidth throttle (tc wrapper)
12. [ ] Helper launchers (nmap, wireshark)

### Phase 7: Polish
13. [ ] Config persistence (JSON profiles)
14. [ ] Log filtering
15. [ ] Error handling / user feedback
16. [ ] Keyboard shortcuts

---

## GUI Architecture

### Navigation
- **Tabs** across top for feature sets
- **Log panel** toggleable (right side split when active, logs in background always)

### Tab Structure

| Tab | Purpose |
|-----|---------|
| **General** | Dashboard: status, interfaces, I/O control, quick actions, devices |
| **Firewall** | iptables builder, presets, rules list |
| **Hotspot** | SSID/pass config, start/stop, connected clients |
| **PXE** | Interface select, boot image, start/stop, client list |
| **Bridge** | Interface picker, create/destroy bridge |
| **Tools** | MAC spoofer, bandwidth throttle, nmap/wireshark helpers |

### Layout — Log Hidden (Default)

```
┌─────────────────────────────────────────────────────────────────────┐
│ [General] [Firewall] [Hotspot] [PXE] [Bridge] [Tools]    [📜 Log]  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─ Status ──────────────────────────────────────────────────────┐  │
│  │ Interface: wlan0 (connected)     IP: 192.168.1.212            │  │
│  │ Gateway: 192.168.1.1             DNS: 1.1.1.1                 │  │
│  │ ▼ 12.4 MB/s  ▲ 1.2 MB/s          Uptime: 3h 24m               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Interfaces ─────────────────────────────────────────────────┐   │
│  │ [wlan0]  Connected  192.168.1.212  [In ▼] [Out ▼] [Block]    │   │
│  │ [eth0]   Down       --            [In ▼] [Out ▼] [Block]     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ Quick Actions ──────────────────────────────────────────────┐   │
│  │ [🔄 Restart Net] [🎲 Random MAC] [📡 Scan Devices]           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─ Devices (6) ────────────────────────────────────────────────┐   │
│  │ 192.168.1.1    router      AA:BB:CC:DD:EE:FF                 │   │
│  │ 192.168.1.212  * this      DE:AD:BE:EF:00:00                 │   │
│  │ 192.168.1.50   phone       11:22:33:44:55:66    [Right-click]│   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Layout — Log Visible (Split View)

```
┌─────────────────────────────────────────────────────────────────────┐
│ [General] [Firewall] [Hotspot] [PXE] [Bridge] [Tools]   [📜 Log ✓] │
├──────────────────────────────────────┬──────────────────────────────┤
│                                      │  ┌─ Log ──────────────────┐  │
│  (Tab content - compressed width)    │  │ dnsmasq: DHCPOFFER..   │  │
│                                      │  │ hostapd: STA connect   │  │
│  Status panel                        │  │ kernel: [UFW BLOCK]    │  │
│  Interfaces list                     │  │ nmap: Scan complete    │  │
│  Quick actions                       │  │                        │  │
│  Device list                         │  │ > _                    │  │
│                                      │  └────────────────────────┘  │
└──────────────────────────────────────┴──────────────────────────────┘
```

### Component Hierarchy

```
App
├── HeaderBar (tabs + log toggle)
├── TabContainer
│   ├── GeneralTab
│   │   ├── StatusPanel
│   │   ├── InterfaceList
│   │   ├── QuickActions
│   │   └── DeviceList
│   ├── FirewallTab
│   │   ├── RuleBuilder
│   │   ├── PresetSelector
│   │   └── RulesList
│   ├── HotspotTab
│   │   ├── ConfigPanel (SSID, pass, channel)
│   │   ├── Controls (start/stop)
│   │   └── ClientList
│   ├── PXETab
│   │   ├── ConfigPanel (interface, image)
│   │   ├── Controls
│   │   └── ClientList
│   ├── BridgeTab
│   │   ├── InterfacePicker
│   │   └── BridgeControls
│   └── ToolsTab
│       ├── MACSpoofPanel
│       ├── BandwidthPanel
│       └── HelperButtons (nmap, wireshark)
└── LogPanel (toggled, right side)
    ├── LogView (scrollable)
    └── CommandInput
```

### Log Panel Behavior
- Always logging in background (even when hidden)
- Toggle shows/hides split view
- Filterable by source (dnsmasq, hostapd, kernel, etc.)
- Optional: command input at bottom for quick terminal access
