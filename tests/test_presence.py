"""Adaptive presence detection — backoff math and state transitions.

No real network: ping is either monkeypatched out entirely, or exercised with a
mocked subprocess so no packets are ever sent.
"""

import pytest

from netpulse.config import Config
from netpulse.db import Database
from netpulse.presence import StateMonitor


@pytest.fixture
def monitor(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    cfg = Config(online_check_interval=10, offline_check_interval=120, max_offline_backoff=600)
    m = StateMonitor(db, cfg)
    m.update_devices([{"mac": "m", "ip": "10.0.0.5", "vendor": "Apple"}])
    yield m
    db.close()


def force_due(monitor):
    """Reset the per-device check clock so the next check_all() runs immediately."""
    monitor.last_checks = {}


def test_new_device_starts_at_online_interval(monitor):
    assert monitor.backoff["m"] == monitor.config.online_check_interval


def test_offline_backoff_doubles_and_caps(monitor):
    monitor._ping = lambda ip: False
    seen = []
    for _ in range(8):
        force_due(monitor)
        monitor.check_all()
        seen.append(monitor.backoff["m"])
    # starts at 10, doubles each miss, capped at max_offline_backoff (600)
    assert seen == [20, 40, 80, 160, 320, 600, 600, 600]
    assert monitor.devices["m"]["state"] == "offline"


def test_coming_online_resets_backoff(monitor):
    monitor._ping = lambda ip: False
    force_due(monitor)
    monitor.check_all()
    assert monitor.backoff["m"] > monitor.config.online_check_interval
    monitor._ping = lambda ip: True
    force_due(monitor)
    monitor.check_all()
    assert monitor.backoff["m"] == monitor.config.online_check_interval
    assert monitor.devices["m"]["state"] == "online"


def test_state_change_persisted_to_db(monitor):
    monitor._ping = lambda ip: True
    force_due(monitor)
    monitor.check_all()
    row = next(d for d in monitor.db.get_devices() if d["mac"] == "m")
    assert row["state"] == "online"


def test_get_device_count(monitor):
    monitor._ping = lambda ip: True
    force_due(monitor)
    monitor.check_all()
    assert monitor.get_device_count() == (1, 0)
    monitor._ping = lambda ip: False
    force_due(monitor)
    monitor.check_all()
    assert monitor.get_device_count() == (0, 1)


def test_ping_uses_subprocess_and_reads_returncode(monkeypatch, monitor):
    calls = {}

    class Result:
        def __init__(self, rc):
            self.returncode = rc

    def fake_run(cmd, **kwargs):
        calls["cmd"] = cmd
        return Result(0)

    monkeypatch.setattr("netpulse.presence.subprocess.run", fake_run)
    assert monitor._ping("10.0.0.5") is True
    assert calls["cmd"][0] == "ping"
    assert "10.0.0.5" in calls["cmd"]

    monkeypatch.setattr("netpulse.presence.subprocess.run", lambda cmd, **k: Result(1))
    assert monitor._ping("10.0.0.5") is False
