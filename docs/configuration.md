# Configuration

Netpulse is configured from three sources, in order of **increasing** precedence:

1. **Built-in defaults** — the values baked into `netpulse.config.Config`.
2. **Config file** — an INI file (see below).
3. **Command-line flags** — the highest priority; only flags you actually pass override
   anything.

Anything left unset at every level falls back to the built-in default.

## The config file

- Format: **INI** (parsed with Python's stdlib `configparser`).
- Location: pass `--config PATH`, or drop a file at **`/etc/netpulse/netpulse.conf`**, which
  is loaded automatically when present. A missing default path is fine; a missing *explicit*
  `--config` path is an error.
- **Section names are cosmetic.** Keys are read from every section, so you only need to keep
  them wherever they read well. The names below (`[network]`, `[discovery]`, …) match the
  shipped example.
- **Values are typed** to match each setting: integers, floats, booleans
  (`true/false/yes/no/on/off/1/0`), and comma-separated lists.
- **Unknown keys and unparseable values are warned about and skipped**, never fatal — the
  default is kept.

A complete, commented sample ships at
[`packaging/netpulse.conf.example`](../packaging/netpulse.conf.example); it reproduces the
defaults exactly.

## Keys

### `[network]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | str | `auto` | Interface to monitor. `auto` selects the first interface with a default route. Override with `-i/--interface`. |
| `target_subnet` | str | `auto` | Subnet to sweep, in CIDR. `auto` derives it from the interface's address and netmask. Override with `-s/--subnet`. |
| `exclude_macs` | list | *(empty)* | MAC addresses to ignore entirely (comma-separated). |
| `exclude_ips` | list | *(empty)* | IP addresses to ignore entirely (comma-separated). |

### `[discovery]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `discovery_interval` | int | `60` | Seconds between full ARP sweeps. Override with `--discovery-interval`. |
| `discovery_timeout` | float | `3.0` | ARP response timeout per sweep (seconds). |

### `[presence]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `online_check_interval` | int | `10` | Seconds between ICMP checks for devices currently **online**. Override with `--online-interval`. |
| `offline_check_interval` | int | `120` | Base backoff (seconds) for **offline** devices; used as the starting point when a device first goes offline. Override with `--offline-interval`. |
| `ping_timeout` | float | `1.0` | ICMP timeout per device (seconds). |
| `ping_count` | int | `1` | ICMP echo requests per check. |
| `max_offline_backoff` | int | `600` | Upper bound on the offline backoff (seconds). The interval doubles on each consecutive miss until it reaches this cap. |

### `[bandwidth]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bandwidth_interval` | int | `5` | Seconds between bandwidth samples. Override with `--bw-interval`. |
| `use_iptables` | bool | `true` | Enable per-device iptables accounting (requires root/`CAP_NET_ADMIN`). Interface-level sampling via `psutil` works regardless. Disable from the CLI with `--no-iptables`. See the note in the README's *Status & limitations*. |
| `iptables_chain` | str | `NETPULSE_INPUT` | Name of the iptables chain Netpulse creates and manages. |

### `[database]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_path` | str | `/var/lib/netpulse/netpulse.db` | SQLite database path. The parent directory is created if needed. Override with `--db`. |
| `db_retention_days` | int | `90` | Days of bandwidth/state history to keep. Older samples — and stale **offline** devices — are pruned hourly. Override with `--retention`. |

### `[reporting]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `export_dir` | str | `/var/lib/netpulse/exports` | Directory for JSON/CSV snapshots. Created if needed. Override with `--export-dir`. |
| `json_export_interval` | int | `300` | Seconds between automatic JSON snapshot writes. |
| `csv_export_interval` | int | `3600` | Seconds between automatic CSV snapshot writes. |

### `[daemon]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `pid_file` | str | `/var/run/netpulse.pid` | PID file path, written in `--daemonize` mode and removed on clean shutdown. Override with `--pidfile`. |
| `log_file` | str | `/var/log/netpulse.log` | Log file path. An empty value logs to stderr. Override with `--log`. |
| `log_level` | str | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, or `ERROR`. Override with `--log-level`. |
| `daemonize` | bool | `false` | Fork into the background on startup. Usually set via `-d/--daemonize` rather than the file. |

## CLI overrides

Every flag that maps to a setting overrides both the file and the defaults. Flags you don't
pass leave the lower-precedence value untouched — so a config file's `use_iptables = false`
stays in effect unless you pass a flag that changes it. Run `netpulse --help` for the
complete list.

## Example

`/etc/netpulse/netpulse.conf`:

```ini
[network]
interface = eth0
target_subnet = 192.168.1.0/24
exclude_ips = 192.168.1.1

[presence]
online_check_interval = 15
max_offline_backoff = 900

[database]
db_retention_days = 30
```

Run with a one-off override:

```bash
sudo netpulse --config /etc/netpulse/netpulse.conf --online-interval 5
```

Here `online_check_interval` resolves to `5` (CLI beats the file's `15`), `interface` to
`eth0` (file beats the `auto` default), and everything else to its built-in default.
