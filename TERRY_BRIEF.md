# Build Brief — Netpulse

**Agent:** Terry
**Repo:** `netpulse`
**Mode:** Greenfield scaffold from a single-file prototype

---

## Status — kickoff

**Started:** 2026-08-18 · **Branch:** `terry/terry-brief-update-6kw2nc` · **Phase:** docs complete

Repo baseline established. The prototype and its systemd unit are checked in as the
starting point for the split described in §3.

**Baseline facts (from the prototype):**

- `prototype-netmon.py` — 2999 lines, single file. Clean class seams already present:
  `Config` (23 keys), `Database`, `ARPDiscoverer`, `StateMonitor`, `BandwidthMonitor`,
  `Exporter`, `NetMonDaemon`, plus network utils, `lookup_vendor`, `setup_logging`,
  `daemonize`, and `run_live_display`.
- `OUI_VENDORS` — ~1900 embedded MAC-prefix entries. Lifts cleanly into `oui.py`.
- `prototype-netmon.service` — Type=forking unit, hardened
  (`NoNewPrivileges`, `CapabilityBoundingSet`, `PrivateTmp`); paths still `netmon.*`,
  to be renamed and reconciled in `packaging/netpulse.service`.

**Progress log:**

- [x] Repo baseline committed (prototype + service unit + this brief)
- [x] §4.1 Package split into `netpulse/` modules — monolith broken along class
      seams into 12 modules; `netmon`→`netpulse` renamed everywhere; OUI table
      (1909 entries) lifted verbatim; prototype `parse_args` indentation bug
      fixed; full import graph + DB/export smoke-tested. No behavior change.
- [x] §4.2 Config file loading + precedence — INI via stdlib `configparser`
      (chosen over TOML so 3.9–3.12 need no `tomli` fallback); `load_config()`
      layers defaults < file < CLI; typed coercion, comma-lists, unknown-key
      warnings; `--config`/`--version` added; `packaging/netpulse.conf.example`
      ships all 23 keys and round-trips to defaults. Precedence verified.
- [x] §4.3 CLI polish — `--export json|csv` added (one-shot dump of stored state,
      no scan/root, short-circuits before the daemon is built); foreground `run`
      documented as the default; `--daemonize`/`--live`/`--config`/`--version`/
      `--snapshot` all present; epilog examples refreshed. Also fixed G3.
- [x] §4.4 Graceful capability checks + G2 — startup warns on missing root
      (CAP_NET_RAW/CAP_NET_ADMIN); iptables init now *probes* usability so a
      missing binary or denied permission disables only per-device accounting
      (interface-level + presence keep running); termination routed through an
      idempotent `shutdown()` that cleans the chain and PID file. Verified.
- [x] §4.5 systemd unit — `packaging/netpulse.service`: renamed netmon→netpulse;
      ExecStart `--pidfile` == `PIDFile` == /var/run/netpulse.pid; `ReadWritePaths`
      now covers state dir + log + pid file; hardening (NoNewPrivileges, PrivateTmp,
      CapabilityBoundingSet/Ambient) preserved.
- [x] §4.6 Tests — 39 pytest cases across config precedence, OUI lookup, DB
      upsert/history/retention, presence backoff + mocked ping, JSON/CSV export.
      No network, no root, no scapy/psutil/netifaces (only dep-free modules
      under test). Surfaced and fixed G5 (upsert update-path crash).
- [x] §4.7 CI + packaging — `pyproject.toml` (PEP 621, console script
      `netpulse=netpulse.cli:main`, dynamic version from `__init__`, ruff+pytest
      config), `requirements.txt`, and `.github/workflows/ci.yml` running ruff +
      pytest on 3.9–3.12 unprivileged. Wheel builds (v1.0.0); lint clean after
      removing 4 dead-code findings; both CI steps reproduced green locally.
- [x] §5 README — pitch, live-display ASCII, features, requirements, install
      (pip + systemd), quickstart, config table, data & privacy, export formats,
      status & limitations (honest re: per-device bandwidth / G1), uninstall.
- [x] Docs/CHANGELOG/LICENSE — `docs/configuration.md` (all 23 keys), `CHANGELOG.md`
      (1.0.0), MIT `LICENSE`; retired the `prototype-netmon.*` reference files.

---

## Known gaps (carried from prototype review)

These are real defects found while reading the prototype end-to-end — **not**
behavior worth "preserving" in the refactor sense. Logged here so they don't get
lost. The split (§4.1) kept them intact deliberately; they get fixed in their own
commits so the diffs stay honest.

- **G1 — Per-device bandwidth was a stub.** **FIXED**: `BandwidthMonitor` now installs two
  targetless counting rules per discovered IP (`-s IP` uploads, `-d IP` downloads), flushes
  the chain on init for a clean slate, parses `iptables -L -n -v -x` robustly (source/dest
  are the last two columns regardless of a target column), and differences successive
  cumulative counts into real rx/tx rates (clamping counter resets). `psutil` is now an
  optional import so the module loads/tests without it. New `tests/test_bandwidth.py` (7
  cases) covers rule install, parsing, rate math, counter reset, and the psutil-absent
  guard. Scope is documented honestly: iptables INPUT/FORWARD only sees traffic to/from or
  forwarded through the host (best on a gateway) — inherent, not a defect.
- **G2 — Daemon leaks iptables state on stop.** ~~`daemonize()` installs a SIGTERM/SIGINT
  handler that only unlinks the PID file and `sys.exit(0)`; it never calls
  `daemon.shutdown()`, so `cleanup_iptables()` is skipped.~~ **FIXED** (with §4.4):
  removed the leaky handler from `daemonize()`; `NetpulseDaemon` now installs its own
  SIGTERM/SIGINT handlers that route through `shutdown()`, which is idempotent and also
  drops the PID file. `systemctl stop` now tears down the chain cleanly.
- **G3 — Dead code in discovery merge.** **FIXED** (with §4.3): removed the empty
  `# Mark unreachable devices` / `pass` block (and the now-unused `discovered_macs`
  set) from `NetpulseDaemon._discovery_cycle()`; replaced with a comment stating the
  intent (ping decides when a silent device flips offline).
- **G5 — Device upsert crashed on the update path.** **FOUND + FIXED** (during §4.6):
  `Database.upsert_device` selected only `(state, state_changed)` yet read
  `row["first_seen"]`, so every re-observation of a known device raised
  `No item with that key`. `StateMonitor.check_all`'s broad `except` swallowed it,
  pinning device state at `unknown` and freezing the offline backoff. One-line fix
  (select `first_seen` too); regression-covered by the new DB/presence tests.
- **G4 — Dependency friction.** `netifaces` is effectively unmaintained and won't build
  cleanly on modern toolchains (confirmed here); `psutil` already exposes interface
  addresses and `scapy` is heavy for one ARP sweep. Not blocking, but worth revisiting
  before 1.0 — a lighter dependency set makes this easier to self-host.

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
