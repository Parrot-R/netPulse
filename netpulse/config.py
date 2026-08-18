"""Configuration for Netpulse.

Holds the :class:`Config` dataclass with all tunables and their defaults, plus
:func:`load_config`, which layers three sources in increasing precedence:

    dataclass defaults  <  config file  <  CLI overrides

The config file is INI (parsed with the stdlib :mod:`configparser`, so it works
identically on every supported Python without extra dependencies). Section names
are cosmetic: keys from *all* sections are flattened onto the dataclass, so a
user never has to remember which section a key lives in. Unknown keys and
unparseable values are warned about and skipped, never fatal.
"""

import configparser
import logging
import os
from dataclasses import dataclass, field, fields
from typing import Dict, List, Optional

log = logging.getLogger("netpulse")

#: Default location searched when no ``--config`` is given. Missing is fine.
DEFAULT_CONFIG_PATH = "/etc/netpulse/netpulse.conf"


@dataclass
class Config:
    # Network
    interface: str = "auto"            # auto = first non-loopback interface
    target_subnet: str = "auto"        # auto = derived from interface CIDR
    exclude_macs: List[str] = field(default_factory=list)
    exclude_ips: List[str] = field(default_factory=list)

    # Discovery
    discovery_interval: int = 60       # seconds between full ARP sweeps
    discovery_timeout: float = 3.0     # ARP timeout per sweep

    # Online/Offline
    online_check_interval: int = 10    # seconds between checks for ONLINE devices
    offline_check_interval: int = 120  # seconds between checks for OFFLINE devices (backoff)
    ping_timeout: float = 1.0          # ICMP timeout per device
    ping_count: int = 1               # ICMP echo requests per check
    max_offline_backoff: int = 600     # cap backoff at 10 min

    # Bandwidth
    bandwidth_interval: int = 5        # seconds between bandwidth samples
    use_iptables: bool = True          # per-device via iptables (requires root)
    iptables_chain: str = "NETPULSE_INPUT"

    # Database
    db_path: str = "/var/lib/netpulse/netpulse.db"
    db_retention_days: int = 90

    # Reporting
    export_dir: str = "/var/lib/netpulse/exports"
    json_export_interval: int = 300    # 5 min
    csv_export_interval: int = 3600    # 1 hr

    # Daemon
    pid_file: str = "/var/run/netpulse.pid"
    log_file: str = "/var/log/netpulse.log"
    log_level: str = "INFO"
    daemonize: bool = False


# ─── Value coercion ──────────────────────────────────────────────────────────

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _coerce(current, raw: str):
    """Coerce an INI string to the type of the field's current (default) value.

    ``bool`` is checked before ``int`` because ``bool`` is a subclass of ``int``.
    List fields are comma-separated. Raises ``ValueError`` on a bad value so the
    caller can warn and skip.
    """
    if isinstance(current, bool):
        val = raw.strip().lower()
        if val in _TRUE:
            return True
        if val in _FALSE:
            return False
        raise ValueError(f"expected a boolean, got {raw!r}")
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, list):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


def _apply_file(cfg: "Config", path: str) -> None:
    """Overlay INI values from *path* onto *cfg* in place."""
    parser = configparser.ConfigParser()
    with open(path) as fh:
        parser.read_file(fh)

    valid = {f.name for f in fields(Config)}
    for section in parser.sections():
        for key, raw in parser.items(section):
            if key not in valid:
                log.warning("unknown config key %r in [%s]; ignoring", key, section)
                continue
            try:
                setattr(cfg, key, _coerce(getattr(cfg, key), raw))
            except ValueError as exc:
                log.warning("bad value for %r in [%s]: %s; keeping default",
                            key, section, exc)


def load_config(path: Optional[str] = None,
                cli_overrides: Optional[Dict[str, object]] = None) -> "Config":
    """Build a :class:`Config` from defaults, an optional file, and CLI overrides.

    Precedence (low to high): dataclass defaults, then the config file, then
    ``cli_overrides``. If *path* is given explicitly it must exist (a missing
    explicit path is an error); the default path is loaded only if present.
    ``cli_overrides`` values that are ``None`` are treated as "not provided" and
    do not override anything.
    """
    cfg = Config()

    file_path = path if path is not None else DEFAULT_CONFIG_PATH
    if os.path.exists(file_path):
        _apply_file(cfg, file_path)
    elif path is not None:
        raise FileNotFoundError(f"config file not found: {file_path}")

    if cli_overrides:
        valid = {f.name for f in fields(Config)}
        for key, value in cli_overrides.items():
            if value is None or key not in valid:
                continue
            setattr(cfg, key, value)

    return cfg
