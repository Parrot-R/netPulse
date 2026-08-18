"""Bandwidth accounting: per-interface via psutil, per-device via iptables.

Per-device accounting installs two counting rules per discovered IP in a
dedicated chain — one matching the device as source (its uploads) and one as
destination (its downloads) — then reads the chain's byte counters and
differences successive samples into rates.

Scope: iptables' INPUT/FORWARD hooks only see traffic to/from this host or
*forwarded through* it. Running on a gateway/router therefore accounts the LAN's
internet usage; running on an ordinary host sees only that host's own traffic.
That visibility is inherent to the iptables approach, not a bug.
"""

import logging
import subprocess
import time
from typing import Dict, Tuple

try:
    import psutil
except ImportError:  # keep the module importable; interface sampling degrades
    psutil = None

from netpulse.config import Config
from netpulse.db import Database

log = logging.getLogger("netpulse")


class BandwidthMonitor:
    """Tracks bandwidth at interface level (psutil) and per-device (iptables)."""

    def __init__(self, db: Database, config: Config, iface: str):
        self.db = db
        self.config = config
        self.iface = iface
        self.prev_iface_counters: Dict[str, Tuple[int, int]] = {}
        self.prev_time = time.time()
        self._warned_no_psutil = False

        # iptables per-IP tracking
        self.iptables_initialized = False
        self.tracked_ips: set = set()                       # IPs we've added rules for
        self.prev_device_counts: Dict[str, Tuple[int, int]] = {}  # ip -> (rx_bytes, tx_bytes)
        self.prev_device_time = time.time()
        if config.use_iptables:
            self._init_iptables()

    def _init_iptables(self):
        """Create the iptables chain for per-IP accounting.

        Probes iptables usability first so a missing binary or a lack of
        privileges disables only per-device accounting (with a clear warning);
        interface-level sampling via psutil keeps working regardless.
        """
        chain = self.config.iptables_chain

        # Probe: is iptables present and usable by this process?
        try:
            probe = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True, text=True, check=False
            )
        except FileNotFoundError:
            log.warning("iptables not found; per-device accounting disabled "
                        "(interface-level bandwidth still active)")
            return
        except Exception as e:
            log.warning("iptables probe failed: %s; per-device accounting disabled "
                        "(interface-level bandwidth still active)", e)
            return

        if probe.returncode != 0:
            detail = (probe.stderr or "").strip() or "permission denied"
            log.warning("iptables not usable (%s); per-device accounting disabled. "
                        "Root or CAP_NET_ADMIN is required. Interface-level "
                        "bandwidth still active.", detail)
            return

        # Usable: create the chain, clear any stale rules from a previous run, and
        # hook it into INPUT/FORWARD.
        try:
            # Create chain (non-zero return just means it already exists).
            subprocess.run(
                ["iptables", "-N", chain],
                capture_output=True, text=True, check=False
            )
            # Start from a clean slate so restarts don't accumulate rules.
            subprocess.run(
                ["iptables", "-F", chain],
                capture_output=True, text=True, check=False
            )
            for hook in ["INPUT", "FORWARD"]:
                existing = subprocess.run(
                    ["iptables", "-C", hook, "-j", chain],
                    capture_output=True, text=True, check=False
                )
                if existing.returncode != 0:
                    subprocess.run(
                        ["iptables", "-I", hook, "-j", chain],
                        capture_output=True, text=True, check=False
                    )
            self.iptables_initialized = True
            log.info("iptables accounting chain initialized")
        except Exception as e:
            log.warning("iptables init failed: %s; per-device accounting disabled", e)

    def _ensure_device_rules(self, devices: Dict[str, Dict]):
        """Add per-IP counting rules for any device we're not tracking yet.

        Two targetless rules per IP — ``-s IP`` (the device's uploads) and
        ``-d IP`` (its downloads). Targetless rules only tally bytes and fall
        through to the next rule, so a packet between two tracked devices is
        counted for both endpoints.
        """
        if not self.iptables_initialized:
            return
        chain = self.config.iptables_chain
        for device in devices.values():
            ip = device.get("ip")
            if not ip or ip in self.tracked_ips:
                continue
            added_ok = True
            for match in (["-s", ip], ["-d", ip]):
                check = subprocess.run(
                    ["iptables", "-C", chain, *match],
                    capture_output=True, text=True, check=False
                )
                if check.returncode != 0:
                    res = subprocess.run(
                        ["iptables", "-A", chain, *match],
                        capture_output=True, text=True, check=False
                    )
                    if res.returncode != 0:
                        added_ok = False
                        log.warning("could not add accounting rule for %s: %s",
                                    ip, (res.stderr or "").strip())
            if added_ok:
                self.tracked_ips.add(ip)

    def _get_iptables_counts(self) -> Dict[str, Dict[str, int]]:
        """Read cumulative per-IP byte counts from the accounting chain.

        Source and destination are always the final two columns of an
        ``iptables -L -n -v -x`` data line, whether or not a target column is
        present, so we index from the end rather than by a fixed position.
        """
        result: Dict[str, Dict[str, int]] = {}
        if not self.iptables_initialized:
            return result
        chain = self.config.iptables_chain
        try:
            output = subprocess.run(
                ["iptables", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True, check=True
            ).stdout
        except Exception as e:
            log.warning("iptables read failed: %s", e)
            return result

        for line in output.splitlines():
            s = line.strip()
            if not s or s.startswith("Chain") or s.startswith("pkts"):
                continue
            tokens = s.split()
            if len(tokens) < 8:
                continue
            try:
                bytes_val = int(tokens[1])
            except ValueError:
                continue
            src = tokens[-2].split("/")[0]   # strip any /mask
            dst = tokens[-1].split("/")[0]
            if src in self.tracked_ips:
                result.setdefault(src, {"rx": 0, "tx": 0})["tx"] += bytes_val
            if dst in self.tracked_ips:
                result.setdefault(dst, {"rx": 0, "tx": 0})["rx"] += bytes_val
        return result

    def sample_interface(self):
        """Sample interface-level bandwidth and store to DB."""
        if psutil is None:
            if not self._warned_no_psutil:
                log.warning("psutil not installed; interface bandwidth disabled")
                self._warned_no_psutil = True
            return

        now = time.time()
        elapsed = now - self.prev_time
        if elapsed < 0.1:
            return

        try:
            counters = psutil.net_io_counters(pernic=True).get(self.iface)
            if not counters:
                return

            rx_bytes = counters.bytes_recv
            tx_bytes = counters.bytes_sent

            prev_rx, prev_tx = self.prev_iface_counters.get(self.iface, (rx_bytes, tx_bytes))
            rx_rate = (rx_bytes - prev_rx) / elapsed
            tx_rate = (tx_bytes - prev_tx) / elapsed

            self.db.record_interface_bw(self.iface, rx_bytes, tx_bytes, rx_rate, tx_rate)

            self.prev_iface_counters[self.iface] = (rx_bytes, tx_bytes)
            self.prev_time = now

        except Exception as e:
            log.warning(f"Interface bandwidth sample failed: {e}")

    def sample_per_device(self, devices: Dict[str, Dict]):
        """Account per-device bandwidth: ensure rules, read counts, store rates."""
        if not self.iptables_initialized:
            return

        self._ensure_device_rules(devices)

        now = time.time()
        elapsed = now - self.prev_device_time
        if elapsed < 0.1:
            return

        ip_counts = self._get_iptables_counts()
        for mac, device in devices.items():
            ip = device.get("ip")
            if not ip or ip not in ip_counts:
                continue
            rx_bytes = ip_counts[ip]["rx"]
            tx_bytes = ip_counts[ip]["tx"]
            prev_rx, prev_tx = self.prev_device_counts.get(ip, (rx_bytes, tx_bytes))
            # Clamp negatives so a counter reset (e.g. chain reflushed) reads 0,
            # not a huge spike.
            rx_rate = max(0.0, rx_bytes - prev_rx) / elapsed
            tx_rate = max(0.0, tx_bytes - prev_tx) / elapsed
            self.prev_device_counts[ip] = (rx_bytes, tx_bytes)
            self.db.record_bandwidth(
                mac=mac, ip=ip,
                rx_bytes=rx_bytes, tx_bytes=tx_bytes,
                rx_rate=rx_rate, tx_rate=tx_rate,
            )

        self.prev_device_time = now

    def cleanup_iptables(self):
        """Remove iptables chain on shutdown."""
        if not self.iptables_initialized:
            return
        try:
            chain = self.config.iptables_chain
            for hook in ["INPUT", "FORWARD"]:
                subprocess.run(
                    ["iptables", "-D", hook, "-j", chain],
                    capture_output=True, check=False
                )
            subprocess.run(["iptables", "-F", chain], capture_output=True, check=False)
            subprocess.run(["iptables", "-X", chain], capture_output=True, check=False)
            log.info("iptables accounting chain removed")
        except Exception:
            pass
