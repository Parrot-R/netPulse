"""Database upsert, state history, and retention pruning."""

import time

import pytest

from netpulse.db import Database


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"), retention_days=30)
    yield d
    d.close()


def only(db):
    rows = db.get_devices()
    assert len(rows) == 1
    return rows[0]


def test_upsert_inserts_device(db):
    db.upsert_device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", vendor="Apple", state="online")
    row = only(db)
    assert row["ip"] == "10.0.0.5"
    assert row["vendor"] == "Apple"
    assert row["state"] == "online"
    assert row["first_seen"] == row["last_seen"]  # first insert


def test_upsert_updates_ip_and_keeps_first_seen(db):
    db.upsert_device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", vendor="Apple")
    first = only(db)["first_seen"]
    time.sleep(0.01)
    db.upsert_device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9", vendor="Apple")
    row = only(db)
    assert row["ip"] == "10.0.0.9"
    assert row["first_seen"] == first          # stable across updates
    assert row["last_seen"] >= first


def test_upsert_does_not_clobber_with_empty_hostname_or_unknown_vendor(db):
    db.upsert_device(mac="m", ip="1.1.1.1", hostname="nas", vendor="Synology", state="online")
    db.upsert_device(mac="m", ip="1.1.1.1", hostname="", vendor="Unknown", state="online")
    row = only(db)
    assert row["hostname"] == "nas"            # empty hostname didn't overwrite
    assert row["vendor"] == "Synology"         # 'Unknown' didn't overwrite


def test_state_change_is_recorded_in_history(db):
    db.upsert_device(mac="m", ip="1.1.1.1", state="online")
    db.upsert_device(mac="m", ip="1.1.1.1", state="offline")
    with db.cursor() as cur:
        cur.execute("SELECT old_state, new_state FROM state_history WHERE mac='m'")
        hist = cur.fetchall()
    assert len(hist) == 1
    assert hist[0]["old_state"] == "online" and hist[0]["new_state"] == "offline"


def test_no_history_row_when_state_unchanged(db):
    db.upsert_device(mac="m", ip="1.1.1.1", state="online")
    db.upsert_device(mac="m", ip="1.1.1.2", state="online")
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM state_history WHERE mac='m'")
        assert cur.fetchone()["n"] == 0


def test_purge_removes_old_samples_but_keeps_recent(db):
    now = time.time()
    old = now - 40 * 86400   # beyond 30-day retention
    recent = now - 1 * 86400
    with db.cursor() as cur:
        for ts in (old, recent):
            cur.execute(
                "INSERT INTO bandwidth_samples (timestamp, mac, ip, rx_bytes, tx_bytes, rx_rate, tx_rate)"
                " VALUES (?, 'm', '1.1.1.1', 0, 0, 0, 0)", (ts,))
    db.purge_old()
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM bandwidth_samples")
        assert cur.fetchone()["n"] == 1


def test_purge_removes_only_stale_offline_devices(db):
    now = time.time()
    stale = now - 40 * 86400
    with db.cursor() as cur:
        cur.execute("INSERT INTO devices (mac, ip, first_seen, last_seen, state, state_changed)"
                    " VALUES ('off', '1.1.1.1', ?, ?, 'offline', ?)", (stale, stale, stale))
        cur.execute("INSERT INTO devices (mac, ip, first_seen, last_seen, state, state_changed)"
                    " VALUES ('on', '1.1.1.2', ?, ?, 'online', ?)", (stale, stale, stale))
    db.purge_old()
    macs = {r["mac"] for r in db.get_devices()}
    assert macs == {"on"}   # stale offline pruned; stale online kept
