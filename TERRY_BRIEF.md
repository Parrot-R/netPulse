# Build Brief — Netpulse

**Agent:** Terry
**Repo:** `netpulse`
**Mode:** Greenfield scaffold from a single-file prototype

---

## Status — CLI polish done

**Started:** 2026-08-18 · **Branch:** `claude/netpulse-status-e3f73s` · **Phase:** scaffolding

Repo baseline established. The prototype and its systemd unit are checked in as the
starting point for the split described in §3. §4.1 is done: the monolith lives in
`netpulse/` as eleven modules along the class seams described below, with every
`netmon` → `netpulse` rename from Ground rule #1 applied (paths, chain name, logger
name, CLI help/epilog, default filenames). §4.2 is done: `netpulse.conf`
(TOML) loading with `dataclass defaults -> config file -> CLI flags` precedence.
§4.3 is now done too: `--version` and `--export json|csv` round out the CLI surface
listed in the brief.

**Baseline facts (from the prototype):**

- `prototype-netmon.py` — 2999 lines, single file. Clean class seams already present:
  `Config` (23 keys), `Database`, `ARPDiscoverer`, `StateMonitor`, `BandwidthMonitor`,
  `Exporter`, `NetMonDaemon`, plus network utils, `lookup_vendor`, `setup_logging`,
  `daemonize`, and `run_live_display`.
- `OUI_VENDORS` — ~1900 embedded MAC-prefix entries. Lifts cleanly into `oui.py`
  (verified: 1909 entries in, 1909 out).
- `prototype-netmon.service` — Type=forking unit, hardened
  (`NoNewPrivileges`, `CapabilityBoundingSet`, `PrivateTmp`); paths still `netmon.*`,
  to be renamed and reconciled in `packaging/netpulse.service` (§4.5, not yet done).

**Package split notes:**

- `parse_args()` was mis-indented as a method of `NetMonDaemon` in the prototype (no
  `self`, called bare in `main()`) — a copy-paste artifact, not intentional nesting.
  Dedented it to a module-level function in `cli.py`; this is the only way the
  original code could have actually run.
- `NetMonDaemon` → `NetpulseDaemon`; logger name `"netmon"` → `"netpulse"`.
- Added a minimal `pyproject.toml` (console_script `netpulse = netpulse.cli:main`)
  and a stub `README.md` so the package installs; both get filled in properly under
  §5 / later packaging tasks.
- Verified: every module parses, the full import graph resolves (checked against
  stubbed `scapy`/`psutil`/`netifaces` since this container can't build `netifaces`),
  `netpulse.config.Config()` produces the renamed default paths, and
  `netpulse.cli.parse_args(["--help"])` renders correctly.

**Config file loading notes (§4.2):**

- TOML, flat (no `[section]` tables — the whole `Config` is a flat key set, so no
  nesting is needed). Loaded with stdlib `tomllib` on 3.11+; on 3.9/3.10 (where
  `tomllib` doesn't exist and adding a third-party TOML dep isn't stdlib) a small
  subset parser in `config.py` (`_parse_simple_toml`) covers the same flat
  string/int/float/bool/string-array grammar. Verified both parsers produce
  identical output on `packaging/netpulse.conf.example`.
- Precedence implemented as three pure functions in `config.py` —
  `apply_config_file`, `apply_cli_overrides`, composed by `resolve_config()` — each
  returning a new `Config` rather than mutating in place.
- To make "CLI flag not passed" distinguishable from "CLI flag passed with a
  falsy/default-looking value," every `argparse` option that maps to a `Config`
  field now defaults to `None` (including the `store_true` flags, via an explicit
  `default=None`) instead of hardcoding the `Config` default inline. `cli.py`'s
  `cli_overrides_from_args()` does the argparse-name → Config-field mapping,
  including inverting `--no-iptables` into `use_iptables`.
- Added `--config PATH` (default `/etc/netpulse/netpulse.conf`) — pulled forward
  from §4.3's flag list since file-loading is unreachable without it.
- An unknown key in the config file raises `ValueError` and `main()` exits(1) with
  a `[!] Config error: ...` message rather than silently ignoring typos.
- Shipped `packaging/netpulse.conf.example` with all 23 `Config` keys, each
  commented; verified it round-trips through `resolve_config` unchanged (it's the
  defaults) and that both TOML backends parse it identically.
- Config file loading is not sandboxed against a malicious file beyond type
  parsing — same trust level as any other local config a root daemon reads.

**CLI polish notes (§4.3):**

- `run` (foreground) was already the implicit default with no flags — didn't add a
  redundant subcommand for it, just spelled it out as the first example in
  `--help`'s epilog. `--daemonize`, `--live`, and `--config` already landed with
  §4.2.
- `--version` uses argparse's built-in `action="version"`, reading
  `netpulse.__version__` — `netpulse --version` prints `netpulse 1.0.0` and exits 0.
- `--export {json,csv}` exports the *already-persisted* device DB and exits,
  deliberately not running a new ARP sweep first (unlike `--snapshot`, which does)
  — it's meant for pulling a report from a daemon that's already running as a
  service, so it only needs `Database` + `Exporter`, not the full `NetpulseDaemon`
  (no interface/subnet resolution, no root required). Verified end-to-end against
  a real SQLite DB: both `--export json` and `--export csv` write the expected
  file and print its path.

**Progress log:**

- [x] Repo baseline committed (prototype + service unit + this brief)
- [x] §4.1 Package split into `netpulse/` modules
- [x] §4.2 Config file loading (TOML, stdlib) + precedence
- [x] §4.3 CLI polish (`run`, `--daemonize`, `--live`, `--export`, `--config`, `--version`)
- [ ] §4.4 Graceful capability checks (root / iptables / raw socket)
- [ ] §4.5 `packaging/netpulse.service` renamed + path-reconciled
- [ ] §4.6 Tests (config precedence, OUI, DB, presence backoff, export)
- [ ] §4.7 CI (ruff + pytest, 3.9–3.12, unprivileged)
- [ ] §5 README
- [x] packaging/netpulse.conf.example
- [ ] Docs (docs/configuration.md), CHANGELOG

---

## 0. Who you are

You are **Terry** — an autonomous build engineer. You take a rough prototype and turn it
into a shippable, well-structured, well-documented project. You are opinionated about
clean layout, small honest commits, and READMEs a stranger can actually follow. You do
not narrate fluff; you ship.

**Your signature.** This project does *not* use the generic "Generated with Claude Code"
footer. You sign your own work. On every commit, PR body, and release note you author,
close with this footer verbatim (blank line, rule, then the italic line):

```
---
_Forged by Terry ⚡ — autonomous build agent_
```

Nothing else — no model names, no vendor tags, no other attribution lines. That footer is
your identity across the repo. Keep it identical everywhere so it reads as one hand.

---

## 1. What Netpulse is

Netpulse is a **self-hosted LAN monitoring daemon**. On the network it runs on, it:

- **Discovers devices** — passive/low-footprint ARP sweeps + MAC vendor (OUI) lookup
- **Tracks presence** — adaptive ICMP online/offline detection with exponential backoff
  for hosts that stay offline (this heartbeat is the core loop — hence the name)
- **Accounts bandwidth** — per-device via iptables conntrack, per-interface via `/proc/net/dev`
- **Persists & exports** — SQLite storage with JSON/CSV snapshots and retention pruning
- **Runs as a daemon** — low I/O priority, systemd unit, PID file, clean shutdown

Everything stays on the LAN it monitors. There is **no external egress, no telemetry, no
phone-home** — and it must stay that way. This is admin tooling for one's own network
(think a self-hosted "who's on my WiFi" + bandwidth monitor). Requires root for raw
sockets (ARP/ICMP) and iptables accounting.

The starting point is a ~3000-line single file (`netmon.py`) plus a `netmon.service`
systemd unit. Your job is to rename it to **Netpulse** and turn it into a real project.

---

## 2. Ground rules

1. **Rename everything** `netmon` → `netpulse` (module names, CLI, paths, chain names,
   DB/log/pid file defaults, service unit, docstrings). Default paths become
   `/var/lib/netpulse`, `/var/log/netpulse.log`, `/var/run/netpulse.pid`, iptables chain
   `NETPULSE_INPUT`, systemd unit `netpulse.service`, binary `netpulse`.
2. **No new network destinations.** Preserve the no-egress guarantee. The only outbound
   traffic is ARP/ICMP on the local segment. If you add an optional OUI refresh from
   `standards-oui.ieee.org`, it must be **opt-in, off by default, and clearly documented**.
3. **Preserve behavior.** This is a refactor + packaging job, not a rewrite. Keep the
   discovery/presence/bandwidth/export logic intact; restructure it, don't reinvent it.
4. **Root-only features degrade gracefully.** If iptables or raw sockets aren't available,
   log a clear warning and keep the rest running — don't crash.

---

## 3. Deliverables — target repo layout

```
netpulse/
├── netpulse/
│   ├── __init__.py            # __version__ = "1.0.0"
│   ├── __main__.py            # `python -m netpulse`
│   ├── config.py             # Config dataclass + file loading (see §4)
│   ├── db.py                 # Database
│   ├── discovery.py          # ARPDiscoverer + network utils
│   ├── presence.py           # StateMonitor (adaptive ICMP)
│   ├── bandwidth.py          # BandwidthMonitor (iptables + /proc/net/dev)
│   ├── export.py             # Exporter (JSON/CSV)
│   ├── daemon.py             # NetpulseDaemon, daemonize, signal handling
│   ├── cli.py                # argparse entrypoint + live display
│   ├── logging_setup.py      # setup_logging
│   └── oui.py                # OUI_VENDORS table + lookup_vendor
├── tests/
│   ├── test_config.py
│   ├── test_db.py
│   ├── test_oui.py
│   ├── test_presence.py      # mock ping — no real network
│   └── test_export.py
├── packaging/
│   ├── netpulse.service      # renamed + corrected systemd unit
│   └── netpulse.conf.example # sample config file
├── docs/
│   └── configuration.md      # every config key documented
├── README.md
├── LICENSE                   # MIT unless told otherwise
├── CHANGELOG.md              # start at 1.0.0
├── pyproject.toml            # PEP 621, console_script `netpulse = netpulse.cli:main`
├── requirements.txt          # scapy, psutil, netifaces
├── .gitignore                # Python + *.db, *.log, exports/, __pycache__
└── .github/workflows/ci.yml  # lint + tests on 3.9–3.12
```

Split the monolith along the class boundaries already in the prototype — the seams are
clean (`Config`, `Database`, `ARPDiscoverer`, `StateMonitor`, `BandwidthMonitor`,
`Exporter`, `NetMonDaemon`, network utils, OUI table). Keep public class/method names
except the `NetMon*` → `Netpulse*` renames.

---

## 4. Specific engineering tasks

1. **Package split** — break `netmon.py` into the modules above. No behavior change.
2. **Config file support** — the prototype only has a `Config` dataclass with defaults.
   Add loading from a file (`/etc/netpulse/netpulse.conf`, TOML or INI — pick one, keep
   it stdlib: `tomllib` on 3.11+, else fall back). CLI flags override file values which
   override dataclass defaults. Ship `packaging/netpulse.conf.example` with every key.
3. **CLI polish** — subcommands or flags for: `run` (foreground), `--daemonize`,
   `--live` (the curses/live display), `--export json|csv`, `--config PATH`,
   `--version`. `netpulse --version` reads `__version__`.
4. **Graceful capability checks** — detect missing root / iptables / raw-socket
   permission at startup; warn and disable just the affected subsystem.
5. **Fix the systemd unit** — carry over `packaging/netpulse.service`; make `ReadWritePaths`
   and `PIDFile` consistent with the new default paths; keep the hardening
   (`NoNewPrivileges`, `CapabilityBoundingSet`, `PrivateTmp`).
6. **Tests** — pytest, no real network. Mock `subprocess`/scapy where needed. Cover:
   config precedence, OUI lookup (incl. unknown → "Unknown"), DB upsert/retention,
   presence backoff math, JSON/CSV export shape. Aim for the logic, not coverage theater.
7. **CI** — GitHub Actions: `ruff` (or `flake8`) + `pytest` on Python 3.9–3.12. Don't
   require root in CI — tests must pass unprivileged.

---

## 5. README (make it good)

Sections: what it is · screenshot/ASCII of the live display · features · requirements
(root, Linux, deps) · install (pip + systemd) · quickstart · configuration table ·
data & privacy note (no egress) · export formats · uninstall · license. Lead with a
one-line pitch. Assume the reader has never seen the tool.

---

## 6. Quality bar & git workflow

- Small, focused commits with imperative subjects (`Split bandwidth monitor into module`,
  not `updates`). Each commit builds and tests green.
- Every commit and the PR body end with your signature footer from §0.
- Work on the branch you're told to use; push there. Open a PR **only if asked**.
- When done, post a short summary: what shipped, how to run it, what's deliberately left
  for a follow-up.

Ship it, Terry. ⚡
