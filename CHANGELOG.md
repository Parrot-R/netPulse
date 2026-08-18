# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-18

First packaged release. Netpulse began as a single-file prototype (`netmon.py`) and is now
a structured, tested, installable Python package.

### Added

- **Package layout** — the monolith split into focused modules: `config`, `db`,
  `discovery`, `presence`, `bandwidth`, `export`, `daemon`, `cli`, `logging_setup`,
  and `oui`.
- **Device discovery** — silent ARP sweeps with offline MAC vendor (OUI) lookup.
- **Presence tracking** — adaptive ICMP checks with exponential backoff for offline hosts.
- **Interface bandwidth** — per-interface RX/TX sampling via `psutil`.
- **Persistence & export** — SQLite storage with retention pruning and JSON/CSV snapshots.
- **Config file support** — INI config loaded from `/etc/netpulse/netpulse.conf` or
  `--config PATH`, with precedence: defaults < file < CLI flags. Every key documented in
  `docs/configuration.md`; sample at `packaging/netpulse.conf.example`.
- **CLI** — foreground run, `--daemonize`, `--live`, `--snapshot`, `--export json|csv`,
  `--config`, `--version`, and per-setting override flags.
- **Daemon** — double-fork daemonize, PID file, and a graceful, signal-driven shutdown.
- **Graceful capability checks** — missing root/iptables/raw-socket permission disables only
  the affected subsystem, with a clear warning, instead of crashing.
- **Packaging & CI** — `pyproject.toml` (console script `netpulse`), `requirements.txt`,
  a hardened systemd unit at `packaging/netpulse.service`, and GitHub Actions running
  ruff + pytest on Python 3.9–3.12.
- **Tests** — pytest suite covering config precedence, OUI lookup, database
  upsert/history/retention, presence backoff, and JSON/CSV export. No network or root
  required.

### Fixed

Relative to the original prototype:

- Device re-observation crashed on the database update path
  (`upsert_device` read `first_seen` without selecting it), which silently pinned device
  state at `unknown` and froze the offline backoff.
- The daemon leaked its iptables chain and PID file on `systemctl stop` because termination
  bypassed the cleanup path; shutdown is now idempotent and routed through signal handlers.
- Removed dead code in the discovery merge and an un-runnable `parse_args` definition that
  had been nested inside the daemon class.

### Known limitations

- **Per-device bandwidth is not yet functional** — the iptables accounting chain has no
  per-IP rules and recorded per-device rates are always zero. Interface-level bandwidth
  works. Tracked for a follow-up release.

[1.0.0]: https://github.com/Parrot-R/netPulse/releases/tag/v1.0.0
