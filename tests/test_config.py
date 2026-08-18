"""Config precedence: dataclass defaults < config file < CLI overrides."""

from pathlib import Path

import pytest

from netpulse.config import Config, load_config

EXAMPLE_CONF = Path(__file__).resolve().parent.parent / "packaging" / "netpulse.conf.example"


def write(tmp_path, text):
    p = tmp_path / "netpulse.conf"
    p.write_text(text)
    return str(p)


def test_defaults_when_no_file_and_no_overrides():
    c = load_config(path=None, cli_overrides=None)
    assert c.interface == "auto"
    assert c.discovery_interval == 60
    assert c.use_iptables is True


def test_file_overrides_defaults_with_type_coercion(tmp_path):
    path = write(tmp_path, """
        [network]
        interface = eth1
        [discovery]
        discovery_interval = 30
        discovery_timeout = 2.5
        [bandwidth]
        use_iptables = no
    """.replace("        ", ""))
    c = load_config(path=path)
    assert c.interface == "eth1"
    assert c.discovery_interval == 30 and isinstance(c.discovery_interval, int)
    assert c.discovery_timeout == 2.5 and isinstance(c.discovery_timeout, float)
    assert c.use_iptables is False
    assert c.db_path == Config().db_path  # untouched default preserved


def test_list_values_are_comma_split(tmp_path):
    path = write(tmp_path, "[network]\nexclude_macs = aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66\n")
    c = load_config(path=path)
    assert c.exclude_macs == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("yes", True), ("1", True), ("on", True),
    ("false", False), ("no", False), ("0", False), ("off", False),
])
def test_bool_coercion_variants(tmp_path, raw, expected):
    path = write(tmp_path, f"[bandwidth]\nuse_iptables = {raw}\n")
    assert load_config(path=path).use_iptables is expected


def test_cli_overrides_beat_file(tmp_path):
    path = write(tmp_path, "[network]\ninterface = eth1\n")
    c = load_config(path=path, cli_overrides={"interface": "wlan0"})
    assert c.interface == "wlan0"


def test_none_overrides_are_ignored(tmp_path):
    path = write(tmp_path, "[bandwidth]\nuse_iptables = no\n")
    c = load_config(path=path, cli_overrides={"use_iptables": None, "db_path": "/tmp/x.db"})
    assert c.use_iptables is False       # None left the file value in place
    assert c.db_path == "/tmp/x.db"      # real override applied


def test_unknown_keys_and_bad_values_are_skipped_not_fatal(tmp_path):
    path = write(tmp_path, """
        [bogus]
        not_a_real_key = 123
        [discovery]
        discovery_interval = not_an_int
    """.replace("        ", ""))
    c = load_config(path=path)          # must not raise
    assert c.discovery_interval == 60   # bad value ignored, default kept


def test_explicit_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        load_config(path="/no/such/netpulse.conf")


def test_default_missing_path_is_silent():
    # DEFAULT_CONFIG_PATH almost certainly doesn't exist in the test env.
    c = load_config(path=None)
    assert c.interface == "auto"


def test_example_file_roundtrips_to_defaults():
    loaded = load_config(path=str(EXAMPLE_CONF))
    base = Config()
    assert vars(loaded) == vars(base)
