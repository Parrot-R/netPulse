# Netpulse

**A self-hosted LAN monitoring daemon — see who's on your network, when they come and go, and how much your link is moving. Everything stays on your LAN; nothing phones home.**

Netpulse quietly watches the network segment it runs on: it discovers devices with
low-footprint ARP sweeps, tracks each one's presence with an adaptive ICMP heartbeat
(hence the name), samples interface bandwidth, and stores it all in SQLite with JSON/CSV
snapshots. It runs in the foreground for a quick look or as a hardened systemd daemon for
the long haul.

> **Privacy first:** Netpulse makes **no external connections**. The only traffic it
> generates is ARP and ICMP on your local segment. No telemetry, no phone-home, no cloud.
> See [Data & privacy](#data--privacy).

---

## The live display

`netpulse --live` gives you an at-a-glance console:

```
========================================================================
  Netpulse Live Monitor - 2026-08-18 14:32:07
  Interface: eth0  Subnet: 192.168.1.0/24
========================================================================
  Devices: 7 total | 5 online | 2 offline | 0 unknown
  Bandwidth: 4.8 MB/s RX / 612.3 KB/s TX
------------------------------------------------------------------------
  IP               MAC                Vendor           State    BW RX        BW TX
------------------------------------------------------------------------
  192.168.1.1      a4:2b:8c:11:22:33  Cisco            online   —            —
  192.168.1.10     3c:22:fb:aa:bb:cc  Apple            online   —            —
  192.168.1.14     b8:27:eb:00:11:22  Raspberry Pi     online   —            —
  192.168.1.20     dc:a6:32:44:55:66  Samsung          offline  —            —
  192.168.1.42     00:1a:11:99:88:77  Google           online   —            —

  Press Ctrl+C to exit
```

Interface-level bandwidth is live. Per-device bandwidth columns are shown for layout but
are not yet populated — see [Status & limitations](#status--limitations).

---

## Features

- **Device discovery** — silent ARP sweeps with MAC vendor (OUI) lookup from an embedded,
  offline table (~1,900 prefixes).
- **Presence tracking** — adaptive ICMP checks: online devices are polled often; offline
  ones back off exponentially (up to a configurable cap) to keep the footprint low.
- **Interface bandwidth** — per-interface RX/TX rates sampled via `psutil`.
- **Persistence & export** — SQLite storage with automatic retention pruning, plus JSON
  and CSV snapshots.
- **Runs as a daemon** — double-fork daemonize, PID file, hardened systemd unit, and a
  clean, signal-driven shutdown that removes its own firewall state.
- **Degrades gracefully** — without root/iptables it disables just the affected subsystem
  (with a clear warning) and keeps the rest running.

---

## Requirements

- **Linux** (uses `/proc`, `iptables`, and raw sockets).
- **Python 3.9+**.
- **Root** (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) for ARP discovery and per-device iptables
  accounting. Interface-level bandwidth and JSON/CSV export work unprivileged.
- Python dependencies: `scapy`, `psutil`, `netifaces`.

> **Note:** `netifaces` builds a C extension; on some systems you may need your
> distribution's Python headers and a compiler (e.g. `build-essential python3-dev`).

---

## Install

```bash
git clone https://github.com/Parrot-R/netPulse.git
cd netPulse
sudo pip install .        # installs the `netpulse` console script (e.g. /usr/local/bin/netpulse)
```

For development, install in editable mode with the test/lint extras:

```bash
pip install -e '.[dev]'
```

### Run as a systemd service

```bash
sudo cp packaging/netpulse.service /etc/systemd/system/netpulse.service
sudo mkdir -p /var/lib/netpulse
sudo systemctl daemon-reload
sudo systemctl enable --now netpulse
journalctl -u netpulse -f          # follow the logs
```

The unit expects the binary at `/usr/local/bin/netpulse` (where a system-wide
`pip install .` places it). If yours lives elsewhere (e.g. a venv), edit `ExecStart`.

---

## Quickstart

```bash
# Foreground, auto-detect interface and subnet (Ctrl+C to stop)
sudo netpulse

# Pick the interface/subnet explicitly
sudo netpulse --interface eth0 --subnet 192.168.1.0/24

# Interactive live console
sudo netpulse --live

# One-shot JSON snapshot after a discovery sweep
sudo netpulse --snapshot

# Export whatever is already stored (no scan, no root needed)
netpulse --export json
netpulse --export csv

# Show the version
netpulse --version
```

Run `netpulse --help` for the full flag list.

---

## Configuration

Netpulse resolves settings in order of increasing precedence:

**built-in defaults  →  config file  →  command-line flags**

Point at a config file with `--config PATH`; if omitted, `/etc/netpulse/netpulse.conf` is
loaded when present. The file is INI; section names are cosmetic (keys are read from every
section). A fully documented sample ships at
[`packaging/netpulse.conf.example`](packaging/netpulse.conf.example), and every key is
described in [`docs/configuration.md`](docs/configuration.md).

Most-used keys:

| Key | Default | Meaning |
|-----|---------|---------|
| `interface` | `auto` | Interface to monitor (`auto` = first with a default route) |
| `target_subnet` | `auto` | CIDR to sweep (`auto` = derived from the interface) |
| `discovery_interval` | `60` | Seconds between full ARP sweeps |
| `online_check_interval` | `10` | Seconds between ICMP checks for online devices |
| `offline_check_interval` | `120` | Base backoff (seconds) for offline devices |
| `max_offline_backoff` | `600` | Cap on the offline backoff (seconds) |
| `use_iptables` | `true` | Enable per-device iptables accounting (needs root) |
| `db_path` | `/var/lib/netpulse/netpulse.db` | SQLite database path |
| `db_retention_days` | `90` | Days of history to keep before pruning |
| `export_dir` | `/var/lib/netpulse/exports` | Where JSON/CSV snapshots are written |
| `log_file` | `/var/log/netpulse.log` | Log file (empty = stderr) |

See [`docs/configuration.md`](docs/configuration.md) for all 23 keys.

---

## Export formats

Netpulse writes two files into `export_dir` (defaults shown):

- **`netpulse_snapshot.json`** — a full snapshot: counts plus a `devices` array.

  ```json
  {
    "timestamp": 1755527527.5,
    "datetime": "2026-08-18T14:32:07",
    "device_count": 7,
    "online_count": 5,
    "offline_count": 2,
    "devices": [
      {
        "mac": "3c:22:fb:aa:bb:cc",
        "ip": "192.168.1.10",
        "hostname": "living-room-apple-tv",
        "vendor": "Apple",
        "state": "online",
        "first_seen": 1755500000.0,
        "last_seen": 1755527520.0,
        "state_changed": 1755527010.0
      }
    ]
  }
  ```

- **`netpulse_devices.csv`** — one row per device with the same columns, for spreadsheets.

The daemon refreshes these on a timer (`json_export_interval` / `csv_export_interval`), and
you can dump them on demand with `netpulse --export json|csv`.

---

## Data & privacy

Netpulse is designed to observe **your own** network and keep everything local:

- **No external egress.** It never contacts the internet. The only packets it emits are ARP
  and ICMP on the local segment.
- **No telemetry.** Nothing about your devices or usage leaves the machine.
- **Your data, your disk.** State lives in a local SQLite database and local JSON/CSV files
  that you control; retention pruning keeps them bounded.

The embedded OUI vendor table is bundled with Netpulse, so vendor lookups are offline too.

Only run Netpulse on networks you are authorized to monitor.

---

## Status & limitations

- **Per-device bandwidth is not yet functional.** The iptables scaffolding exists, but the
  accounting chain has no per-IP rules and recorded per-device rates are always zero, so the
  live display's per-device BW columns are placeholders. Interface-level bandwidth is fully
  working. This is tracked for a follow-up.
- **Linux only.** Netpulse depends on `iptables`, `/proc`, and raw sockets.

---

## Uninstall

```bash
sudo systemctl disable --now netpulse        # if installed as a service
sudo rm -f /etc/systemd/system/netpulse.service
sudo systemctl daemon-reload

sudo pip uninstall netpulse

# Optional: remove stored data and logs
sudo rm -rf /var/lib/netpulse /var/log/netpulse.log /var/run/netpulse.pid
```

If the daemon was ever stopped uncleanly, remove its firewall chain:

```bash
sudo iptables -D INPUT   -j NETPULSE_INPUT 2>/dev/null
sudo iptables -D FORWARD -j NETPULSE_INPUT 2>/dev/null
sudo iptables -F NETPULSE_INPUT 2>/dev/null
sudo iptables -X NETPULSE_INPUT 2>/dev/null
```

---

## License

[MIT](LICENSE) © 2026 Netpulse contributors
