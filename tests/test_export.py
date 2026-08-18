"""JSON and CSV export shape."""

import csv
import json

import pytest

from netpulse.db import Database
from netpulse.export import Exporter


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.upsert_device(mac="a", ip="10.0.0.1", vendor="Apple", state="online")
    db.upsert_device(mac="b", ip="10.0.0.2", vendor="Cisco", state="offline")
    ex = Exporter(db, str(tmp_path / "exports"))
    yield db, ex
    db.close()


def test_export_json_shape(setup):
    _, ex = setup
    path = ex.export_json()
    data = json.loads(path.read_text())
    assert data["device_count"] == 2
    assert data["online_count"] == 1
    assert data["offline_count"] == 1
    assert isinstance(data["devices"], list) and len(data["devices"]) == 2
    assert {"timestamp", "datetime", "devices"} <= data.keys()


def test_export_csv_has_header_and_rows(setup):
    _, ex = setup
    path = ex.export_csv()
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert {"mac", "ip", "vendor", "state"} <= set(rows[0].keys())
    assert {r["mac"] for r in rows} == {"a", "b"}


def test_export_csv_with_no_devices_writes_nothing(tmp_path):
    db = Database(str(tmp_path / "empty.db"))
    ex = Exporter(db, str(tmp_path / "exports"))
    path = ex.export_csv()
    assert not path.exists()   # current behavior: no file when there are no devices
    db.close()


def test_export_paths_land_in_export_dir(setup):
    _, ex = setup
    assert ex.export_json().parent == ex.export_dir
    assert ex.export_csv().parent == ex.export_dir
