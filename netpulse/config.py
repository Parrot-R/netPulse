"""Configuration for Netpulse.

Holds the :class:`Config` dataclass with all tunables and their defaults.
File-based loading and CLI override precedence are layered on top of this in
later work; the dataclass here is the single source of default values.
"""

from dataclasses import dataclass, field
from typing import List


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
