"""Per-device bandwidth accounting: rule installation, parsing, and rate math.

No real iptables: subprocess is faked, so nothing touches the firewall.
"""

import types

import pytest

from netpulse import bandwidth
from netpulse.bandwidth import BandwidthMonitor
from netpulse.config import Config


def bare_monitor(tracked=()):
    """A BandwidthMonitor without running __init__ (no iptables probing)."""
    m = object.__new__(BandwidthMonitor)
    m.config = Config()
    m.db = types.SimpleNamespace(records=[])
    m.db.record_bandwidth = lambda **kw: m.db.records.append(kw)
    m.iptables_initialized = True
    m.tracked_ips = set(tracked)
    m.prev_device_counts = {}
    m.prev_device_time = 1000.0
    return m


def result(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_ensure_device_rules_adds_src_and_dst_once(monkeypatch):
    m = bare_monitor()
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        # -C (check) fails so -A (add) is issued; -A succeeds
        return result(returncode=1) if "-C" in cmd else result(returncode=0)

    monkeypatch.setattr(bandwidth.subprocess, "run", fake_run)
    devices = {"aa": {"ip": "10.0.0.5"}}
    m._ensure_device_rules(devices)

    added = [c for c in calls if "-A" in c]
    assert ["-s", "10.0.0.5"] == added[0][-2:]
    assert ["-d", "10.0.0.5"] == added[1][-2:]
    assert "10.0.0.5" in m.tracked_ips

    # Second pass: already tracked -> no new iptables calls at all
    calls.clear()
    m._ensure_device_rules(devices)
    assert calls == []


@pytest.mark.parametrize("with_target", [False, True])
def test_get_counts_parses_regardless_of_target_column(monkeypatch, with_target):
    m = bare_monitor(tracked={"192.168.1.10"})
    tgt = "RETURN " if with_target else ""
    out = (
        "Chain NETPULSE_INPUT (2 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        f"      10      1000 {tgt}    all  --  *      *       192.168.1.10         0.0.0.0/0\n"
        f"       5       400 {tgt}    all  --  *      *       0.0.0.0/0            192.168.1.10\n"
    )
    monkeypatch.setattr(bandwidth.subprocess, "run", lambda cmd, **kw: result(stdout=out))
    counts = m._get_iptables_counts()
    # device as source => its uploads (tx); device as dest => its downloads (rx)
    assert counts["192.168.1.10"] == {"tx": 1000, "rx": 400}


def test_untracked_ips_are_ignored(monkeypatch):
    m = bare_monitor(tracked={"192.168.1.10"})
    out = (
        "Chain NETPULSE_INPUT (2 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "      10      1000            all  --  *      *       10.9.9.9             0.0.0.0/0\n"
    )
    monkeypatch.setattr(bandwidth.subprocess, "run", lambda cmd, **kw: result(stdout=out))
    assert m._get_iptables_counts() == {}


def test_sample_per_device_computes_rates(monkeypatch):
    m = bare_monitor(tracked={"10.0.0.5"})
    m._ensure_device_rules = lambda devices: None
    clock = types.SimpleNamespace(t=1000.0)
    monkeypatch.setattr(bandwidth.time, "time", lambda: clock.t)
    m.prev_device_time = 999.0  # constructed a moment earlier, so first sample runs

    counts = {"10.0.0.5": {"rx": 1000, "tx": 500}}
    m._get_iptables_counts = lambda: counts
    devices = {"aa": {"ip": "10.0.0.5"}}

    # First sample establishes a baseline -> rate 0
    m.sample_per_device(devices)
    first = m.db.records[-1]
    assert first["rx_bytes"] == 1000 and first["rx_rate"] == 0 and first["tx_rate"] == 0

    # 10s later, +2000 rx / +1000 tx -> 200 / 100 bytes/s
    clock.t = 1010.0
    counts["10.0.0.5"] = {"rx": 3000, "tx": 1500}
    m.sample_per_device(devices)
    second = m.db.records[-1]
    assert second["rx_rate"] == pytest.approx(200.0)
    assert second["tx_rate"] == pytest.approx(100.0)


def test_counter_reset_clamps_to_zero(monkeypatch):
    m = bare_monitor(tracked={"10.0.0.5"})
    m._ensure_device_rules = lambda devices: None
    clock = types.SimpleNamespace(t=1000.0)
    monkeypatch.setattr(bandwidth.time, "time", lambda: clock.t)
    m.prev_device_time = clock.t
    m.prev_device_counts["10.0.0.5"] = (5000, 5000)  # previous high reading

    m._get_iptables_counts = lambda: {"10.0.0.5": {"rx": 100, "tx": 100}}  # reset
    clock.t = 1010.0
    m.sample_per_device({"aa": {"ip": "10.0.0.5"}})
    rec = m.db.records[-1]
    assert rec["rx_rate"] == 0 and rec["tx_rate"] == 0


def test_sample_interface_without_psutil_is_silent(monkeypatch):
    m = object.__new__(BandwidthMonitor)
    m._warned_no_psutil = False
    monkeypatch.setattr(bandwidth, "psutil", None)
    m.sample_interface()   # must not raise
    assert m._warned_no_psutil is True
