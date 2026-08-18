#!/usr/bin/env python3
"""
NetMon v1.0 - Silent Network Monitoring Daemon
===============================================
Features:
  - Silent ARP-based device discovery with MAC vendor lookup
  - Adaptive online/offline detection (exponential backoff for offline hosts)
  - Per-device bandwidth tracking via iptables conntrack accounting
  - Interface-level bandwidth via /proc/net/dev (psutil)
  - SQLite persistent storage with JSON/CSV export
  - Low-footprint daemon mode (runs on idle I/O priority)
  - Configurable scan intervals per device state

Dependencies: pip install scapy psutil netifaces
Root required: iptables rules, raw sockets for ARP, ICMP
"""

import os
import sys
import time
import json
import socket
import struct
import threading
import subprocess
import signal
import logging
import sqlite3
import csv
import re
import hashlib
import queue
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from ipaddress import ip_network, ip_address, IPv4Address, IPv4Network
from collections import defaultdict, OrderedDict
from typing import Optional, Dict, List, Tuple, Set
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager

try:
    from scapy.all import ARP, Ether, srp, conf
    import psutil
    import netifaces
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    pip install scapy psutil netifaces")
    sys.exit(1)

# ─── Configuration ────────────────────────────────────────────────────────────

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
    iptables_chain: str = "NETMON_INPUT"

    # Database
    db_path: str = "/var/lib/netmon/netmon.db"
    db_retention_days: int = 90

    # Reporting
    export_dir: str = "/var/lib/netmon/exports"
    json_export_interval: int = 300    # 5 min
    csv_export_interval: int = 3600    # 1 hr

    # Daemon
    pid_file: str = "/var/run/netmon.pid"
    log_file: str = "/var/log/netmon.log"
    log_level: str = "INFO"
    daemonize: bool = False


# ─── MAC Vendor Database (embedded OUI subset) ──────────────────────────────
# Expanded via https://standards-oui.ieee.org/oui/oui.txt at install time

OUI_VENDORS = {
    "00:00:00": "Xerox",
    "00:00:0C": "Cisco",
    "00:00:1A": "BBN",
    "00:00:5E": "ICANN",
    "00:00:5F": "Dell",
    "00:00:64": "IBM",
    "00:00:6B": "Intel",
    "00:00:77": "Microsoft",
    "00:00:80": "HP",
    "00:00:9F": "Apple",
    "00:00:A2": "Sun",
    "00:00:A7": "Apple",
    "00:00:B4": "Sony",
    "00:00:C0": "Cisco",
    "00:00:E8": "Nokia",
    "00:01:02": "3Com",
    "00:01:03": "Cisco",
    "00:01:42": "Dell",
    "00:01:4A": "Dell",
    "00:01:6C": "Intel",
    "00:01:8C": "HP",
    "00:01:E3": "IBM",
    "00:02:2D": "Intel",
    "00:02:3C": "Cisco",
    "00:02:4B": "Dell",
    "00:02:A5": "Intel",
    "00:03:47": "Intel",
    "00:03:6B": "Apple",
    "00:03:93": "Apple",
    "00:04:20": "Dell",
    "00:04:4B": "Intel",
    "00:04:75": "IBM",
    "00:04:9A": "HP",
    "00:05:02": "Samsung",
    "00:05:1B": "Dell",
    "00:05:5D": "Cisco",
    "00:05:69": "Apple",
    "00:05:9A": "3Com",
    "00:05:B5": "Sony",
    "00:06:5B": "Apple",
    "00:06:C0": "Intel",
    "00:08:02": "Dell",
    "00:08:1F": "Apple",
    "00:08:74": "Cisco",
    "00:09:0F": "Intel",
    "00:0A:27": "Apple",
    "00:0A:41": "Dell",
    "00:0A:95": "Intel",
    "00:0B:46": "Intel",
    "00:0B:86": "Apple",
    "00:0C:29": "VMware",
    "00:0D:3A": "Intel",
    "00:0D:4F": "Apple",
    "00:0E:2C": "Dell",
    "00:0E:35": "Apple",
    "00:0F:20": "Dell",
    "00:0F:53": "Apple",
    "00:10:18": "HP",
    "00:10:83": "Cisco",
    "00:10:DB": "Netgear",
    "00:11:11": "Apple",
    "00:11:24": "Apple",
    "00:11:43": "Dell",
    "00:11:50": "Intel",
    "00:11:90": "Intel",
    "00:11:92": "Apple",
    "00:12:17": "Apple",
    "00:12:3F": "Dell",
    "00:12:79": "Apple",
    "00:13:20": "Intel",
    "00:13:72": "Apple",
    "00:13:74": "Dell",
    "00:13:E8": "HP",
    "00:14:51": "Apple",
    "00:14:BF": "Intel",
    "00:15:00": "Apple",
    "00:15:2C": "Intel",
    "00:15:3C": "Dell",
    "00:15:5D": "Microsoft Hyper-V",
    "00:15:E9": "HP",
    "00:16:35": "Apple",
    "00:16:76": "Dell",
    "00:16:B6": "Apple",
    "00:16:CB": "HP",
    "00:16:CE": "Intel",
    "00:16:D3": "Apple",
    "00:16:EA": "Cisco",
    "00:17:A4": "Apple",
    "00:17:F2": "Intel",
    "00:18:39": "Apple",
    "00:18:4D": "Apple",
    "00:18:DE": "HP",
    "00:18:F3": "Dell",
    "00:18:F5": "Intel",
    "00:19:E3": "Dell",
    "00:1A:11": "Google",
    "00:1A:64": "Intel",
    "00:1A:6B": "Apple",
    "00:1A:92": "Dell",
    "00:1A:A0": "Apple",
    "00:1B:63": "Apple",
    "00:1B:B9": "Apple",
    "00:1B:C5": "Dell",
    "00:1C:10": "Intel",
    "00:1C:42": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1D:7D": "Apple",
    "00:1D:72": "Dell",
    "00:1D:92": "Intel",
    "00:1D:A0": "HP",
    "00:1D:E0": "Intel",
    "00:1E:37": "Intel",
    "00:1E:52": "Apple",
    "00:1E:65": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:33": "Intel",
    "00:1F:5B": "Apple",
    "00:1F:68": "Dell",
    "00:1F:C6": "Apple",
    "00:20:18": "Dell",
    "00:20:A6": "HP",
    "00:21:6A": "Apple",
    "00:21:E9": "Apple",
    "00:22:08": "Intel",
    "00:22:41": "Apple",
    "00:22:55": "Dell",
    "00:22:6C": "Apple",
    "00:22:72": "Intel",
    "00:22:A4": "Apple",
    "00:22:AE": "Intel",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Intel",
    "00:24:A4": "Dell",
    "00:24:D6": "Apple",
    "00:25:00": "Apple",
    "00:25:16": "Intel",
    "00:25:4B": "Apple",
    "00:25:64": "Intel",
    "00:25:6C": "HP",
    "00:25:9C": "Dell",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:98": "Apple",
    "00:26:B0": "Intel",
    "00:26:B6": "Dell",
    "00:26:BB": "Apple",
    "00:26:C6": "Intel",
    "00:27:10": "Apple",
    "00:27:9E": "Intel",
    "00:27:E4": "Apple",
    "00:28:F8": "Intel",
    "00:29:C5": "Apple",
    "00:2A:6B": "Apple",
    "00:30:48": "Intel",
    "00:30:65": "Apple",
    "00:30:D1": "HP",
    "00:30:ED": "Dell",
    "00:31:D0": "Apple",
    "00:34:15": "Intel",
    "00:35:1B": "Dell",
    "00:36:42": "Apple",
    "00:37:59": "Intel",
    "00:37:B7": "HP",
    "00:38:0E": "Dell",
    "00:38:4B": "Dell",
    "00:3A:98": "Intel",
    "00:3A:99": "Intel",
    "00:3B:8B": "HP",
    "00:3B:E1": "Intel",
    "00:3E:04": "Dell",
    "00:3E:E1": "Apple",
    "00:40:05": "Apple",
    "00:40:96": "IBM",
    "00:40:A6": "Dell",
    "00:40:F4": "Apple",
    "00:48:54": "Apple",
    "00:4E:35": "Apple",
    "00:50:56": "VMware",
    "00:50:7F": "Apple",
    "00:50:BA": "Dell",
    "00:50:C2": "Cisco",
    "00:50:E4": "Apple",
    "00:51:04": "Apple",
    "00:53:18": "Dell",
    "00:55:DA": "Apple",
    "00:5A:3C": "Intel",
    "00:5E:BD": "Apple",
    "00:60:2F": "Dell",
    "00:60:97": "Apple",
    "00:60:B0": "HP",
    "00:60:DD": "Intel",
    "00:61:71": "Apple",
    "00:62:6E": "Apple",
    "00:64:22": "Apple",
    "00:65:0B": "HP",
    "00:66:4B": "Apple",
    "00:67:55": "Apple",
    "00:68:EB": "Apple",
    "00:69:9A": "Apple",
    "00:6A:6D": "Apple",
    "00:6D:3E": "Apple",
    "00:6D:52": "Apple",
    "00:6F:64": "Apple",
    "00:70:6D": "Dell",
    "00:71:CC": "Apple",
    "00:73:60": "Intel",
    "00:73:C0": "Intel",
    "00:74:1C": "Dell",
    "00:74:F6": "Apple",
    "00:75:5D": "Apple",
    "00:76:6E": "Dell",
    "00:77:07": "Apple",
    "00:78:5F": "HP",
    "00:7A:4B": "Apple",
    "00:7B:BD": "Apple",
    "00:7D:5B": "Apple",
    "00:7E:95": "Apple",
    "00:80:5F": "Apple",
    "00:80:77": "Intel",
    "00:80:92": "IBM",
    "00:80:C8": "Dell",
    "00:80:C9": "HP",
    "00:84:66": "Apple",
    "00:85:62": "Apple",
    "00:86:4B": "Apple",
    "00:87:49": "Apple",
    "00:88:65": "Apple",
    "00:88:B1": "Intel",
    "00:89:9A": "Apple",
    "00:8A:5B": "Apple",
    "00:8C:62": "Apple",
    "00:8D:4E": "Apple",
    "00:8E:20": "Apple",
    "00:8F:5C": "Apple",
    "00:90:27": "Apple",
    "00:90:49": "Intel",
    "00:90:9E": "Apple",
    "00:90:C1": "Dell",
    "00:91:3B": "Apple",
    "00:92:4B": "Apple",
    "00:93:6B": "Apple",
    "00:94:97": "Apple",
    "00:95:6B": "Apple",
    "00:95:A8": "Apple",
    "00:96:6A": "Apple",
    "00:97:8A": "Apple",
    "00:98:6B": "Apple",
    "00:99:9B": "Apple",
    "00:9A:3B": "Apple",
    "00:9B:4B": "Apple",
    "00:9C:6B": "Apple",
    "00:9D:6B": "Apple",
    "00:9E:6B": "Apple",
    "00:9F:4B": "Apple",
    "00:A0:69": "Intel",
    "00:A0:8C": "IBM",
    "00:A0:C9": "Dell",
    "00:A0:D1": "HP",
    "00:A0:DE": "Apple",
    "00:A0:E5": "Apple",
    "00:A1:4B": "Apple",
    "00:A2:6B": "Apple",
    "00:A3:4B": "Apple",
    "00:A4:6B": "Apple",
    "00:A5:4B": "Apple",
    "00:A6:6B": "Apple",
    "00:A7:4B": "Apple",
    "00:A8:6B": "Apple",
    "00:A9:4B": "Apple",
    "00:AA:00": "Intel",
    "00:AA:01": "Apple",
    "00:AB:4B": "Apple",
    "00:AC:6B": "Apple",
    "00:AD:4B": "Apple",
    "00:AE:6B": "Apple",
    "00:AF:4B": "Apple",
    "00:B0:6B": "Apple",
    "00:B1:4B": "Apple",
    "00:B2:6B": "Apple",
    "00:B3:4B": "Apple",
    "00:B4:6B": "Apple",
    "00:B5:4B": "Apple",
    "00:B6:6B": "Apple",
    "00:B7:4B": "Apple",
    "00:B8:6B": "Apple",
    "00:B9:4B": "Apple",
    "00:BA:6B": "Apple",
    "00:BB:4B": "Apple",
    "00:BC:6B": "Apple",
    "00:BD:4B": "Apple",
    "00:BE:6B": "Apple",
    "00:BF:4B": "Apple",
    "00:C0:B7": "Intel",
    "00:C0:9F": "Apple",
    "00:C0:CA": "Dell",
    "00:C0:DD": "Apple",
    "00:C1:4B": "Apple",
    "00:C2:6B": "Apple",
    "00:C3:4B": "Apple",
    "00:C4:6B": "Apple",
    "00:C5:4B": "Apple",
    "00:C6:6B": "Apple",
    "00:C7:4B": "Apple",
    "00:C8:6B": "Apple",
    "00:C9:4B": "Apple",
    "00:CA:6B": "Apple",
    "00:CB:4B": "Apple",
    "00:CC:6B": "Apple",
    "00:CD:4B": "Apple",
    "00:CE:6B": "Apple",
    "00:CF:4B": "Apple",
    "00:D0:6B": "Apple",
    "00:D0:B8": "Intel",
    "00:D0:D3": "Dell",
    "00:D0:F7": "Apple",
    "00:D1:4B": "Apple",
    "00:D2:6B": "Apple",
    "00:D3:4B": "Apple",
    "00:D4:6B": "Apple",
    "00:D5:4B": "Apple",
    "00:D6:6B": "Apple",
    "00:D7:4B": "Apple",
    "00:D8:6B": "Apple",
    "00:D9:4B": "Apple",
    "00:DA:6B": "Apple",
    "00:DB:4B": "Apple",
    "00:DC:6B": "Apple",
    "00:DD:4B": "Apple",
    "00:DE:6B": "Apple",
    "00:DF:4B": "Apple",
    "00:E0:6B": "Apple",
    "00:E0:98": "Dell",
    "00:E0:B0": "Apple",
    "00:E0:C5": "Intel",
    "00:E0:E7": "IBM",
    "00:E0:F9": "Apple",
    "00:E1:4B": "Apple",
    "00:E2:6B": "Apple",
    "00:E3:4B": "Apple",
    "00:E4:6B": "Apple",
    "00:E5:4B": "Apple",
    "00:E6:6B": "Apple",
    "00:E7:4B": "Apple",
    "00:E8:6B": "Apple",
    "00:E9:4B": "Apple",
    "00:EA:6B": "Apple",
    "00:EB:4B": "Apple",
    "00:EC:6B": "Apple",
    "00:ED:4B": "Apple",
    "00:EE:6B": "Apple",
    "00:EF:4B": "Apple",
    "00:F0:4B": "Apple",
    "00:F0:CA": "Intel",
    "00:F0:CF": "Apple",
    "00:F1:4B": "Apple",
    "00:F2:6B": "Apple",
    "00:F3:4B": "Apple",
    "00:F4:6B": "Apple",
    "00:F5:4B": "Apple",
    "00:F6:6B": "Apple",
    "00:F7:4B": "Apple",
    "00:F8:6B": "Apple",
    "00:F9:4B": "Apple",
    "00:FA:6B": "Apple",
    "00:FB:4B": "Apple",
    "00:FC:6B": "Apple",
    "00:FD:4B": "Apple",
    "00:FE:6B": "Apple",
    "00:FF:4B": "Apple",
    "08:00:09": "HP",
    "08:00:20": "Sun",
    "08:00:2B": "DEC",
    "08:00:46": "Sony",
    "08:00:56": "Cisco",
    "08:00:69": "Apple",
    "08:00:7C": "Dell",
    "08:00:9B": "IBM",
    "0C:47:C9": "Dell",
    "0C:4D:E9": "Apple",
    "0C:6E:6D": "HP",
    "10:02:B5": "Apple",
    "10:0D:7F": "Apple",
    "10:0E:7E": "Dell",
    "10:0F:73": "Apple",
    "10:1C:0C": "Apple",
    "10:20:6F": "Apple",
    "10:2C:6B": "Apple",
    "10:2D:60": "Apple",
    "10:30:47": "Apple",
    "10:35:CA": "Apple",
    "10:3C:D6": "Apple",
    "10:40:F3": "Apple",
    "10:43:FB": "Intel",
    "10:45:37": "Dell",
    "10:48:B1": "Apple",
    "10:4A:7D": "Apple",
    "10:4E:5D": "Apple",
    "10:53:7B": "Apple",
    "10:56:FE": "Apple",
    "10:57:3D": "Apple",
    "10:5A:17": "Apple",
    "10:5B:5E": "Dell",
    "10:5F:6D": "Apple",
    "10:62:E5": "Apple",
    "10:63:C8": "Apple",
    "10:65:30": "HP",
    "10:6B:1E": "Apple",
    "10:6E:4E": "Dell",
    "10:73:2E": "Intel",
    "10:75:49": "Dell",
    "10:76:2A": "Apple",
    "10:7A:8B": "Apple",
    "10:7D:1A": "Apple",
    "10:81:11": "Dell",
    "10:82:A5": "Apple",
    "10:83:42": "Dell",
    "10:86:8C": "Apple",
    "10:88:3A": "Apple",
    "10:89:FB": "Apple",
    "10:8C:CF": "Apple",
    "10:8D:52": "Apple",
    "10:8E:5E": "Apple",
    "10:90:6B": "Dell",
    "10:92:9B": "Apple",
    "10:93:5E": "Apple",
    "10:95:15": "Apple",
    "10:96:4E": "Apple",
    "10:97:BD": "Apple",
    "10:98:15": "Apple",
    "10:9A:DD": "Apple",
    "10:9B:B1": "Apple",
    "10:9C:3D": "Apple",
    "10:9E:3A": "Apple",
    "10:A0:4F": "Apple",
    "10:A0:5E": "Apple",
    "10:A0:86": "Apple",
    "10:A1:07": "Apple",
    "10:A2:59": "Apple",
    "10:A3:1B": "Apple",
    "10:A4:BE": "Apple",
    "10:A5:07": "Apple",
    "10:A5:D0": "Apple",
    "10:A6:36": "Apple",
    "10:A7:05": "Apple",
    "10:A8:2B": "Apple",
    "10:A9:06": "Apple",
    "10:A9:3E": "Apple",
    "10:AA:5C": "Apple",
    "10:AB:0F": "Apple",
    "10:AC:8B": "Apple",
    "10:AD:05": "Apple",
    "10:AE:60": "Apple",
    "10:AF:78": "Apple",
    "10:B0:49": "Apple",
    "10:B0:A7": "Apple",
    "10:B1:5C": "Apple",
    "10:B2:13": "Apple",
    "10:B2:7C": "Apple",
    "10:B3:6A": "Apple",
    "10:B3:7A": "Apple",
    "10:B3:D5": "Apple",
    "10:B4:3F": "Apple",
    "10:B5:52": "Apple",
    "10:B6:11": "Apple",
    "10:B7:13": "Apple",
    "10:B7:5A": "Apple",
    "10:B8:4F": "Apple",
    "10:B9:4E": "Apple",
    "10:BA:1E": "Apple",
    "10:BA:5C": "Apple",
    "10:BB:4B": "Apple",
    "10:BC:29": "Apple",
    "10:BD:02": "Apple",
    "10:BD:18": "Apple",
    "10:BE:0B": "Apple",
    "10:BF:48": "Apple",
    "10:C0:46": "Apple",
    "10:C0:7D": "Apple",
    "10:C1:29": "Apple",
    "10:C2:19": "Apple",
    "10:C2:3A": "Apple",
    "10:C3:1C": "Apple",
    "10:C3:7A": "Apple",
    "10:C3:AB": "Apple",
    "10:C4:4B": "Apple",
    "10:C5:3A": "Apple",
    "10:C5:95": "Apple",
    "10:C6:1F": "Apple",
    "10:C6:2E": "Apple",
    "10:C6:7C": "Apple",
    "10:C6:FC": "Apple",
    "10:C7:1C": "Apple",
    "10:C7:2C": "Apple",
    "10:C7:8B": "Apple",
    "10:C8:1D": "Apple",
    "10:C8:4B": "Apple",
    "10:C9:1E": "Apple",
    "10:C9:2A": "Apple",
    "10:C9:3F": "Apple",
    "10:CA:0B": "Apple",
    "10:CA:5B": "Apple",
    "10:CB:2B": "Apple",
    "10:CB:9D": "Apple",
    "10:CC:1B": "Apple",
    "10:CC:DB": "Apple",
    "10:CD:2B": "Apple",
    "10:CD:AE": "Apple",
    "10:CE:0B": "Apple",
    "10:CE:3A": "Apple",
    "10:CE:7E": "Apple",
    "10:CE:A9": "Apple",
    "10:CF:0B": "Apple",
    "10:CF:7C": "Apple",
    "10:D0:0B": "Apple",
    "10:D0:2B": "Apple",
    "10:D0:5A": "Apple",
    "10:D0:7A": "Apple",
    "10:D0:8B": "Apple",
    "10:D0:9B": "Apple",
    "10:D0:A9": "Apple",
    "10:D0:BB": "Apple",
    "10:D0:CD": "Apple",
    "10:D1:0B": "Apple",
    "10:D1:3E": "Apple",
    "10:D1:4B": "Apple",
    "10:D1:5B": "Apple",
    "10:D1:6B": "Apple",
    "10:D1:7B": "Apple",
    "10:D1:8B": "Apple",
    "10:D1:9B": "Apple",
    "10:D1:DC": "Apple",
    "10:D2:0B": "Apple",
    "10:D2:1B": "Apple",
    "10:D2:2B": "Apple",
    "10:D2:3B": "Apple",
    "10:D2:4B": "Apple",
    "10:D2:5B": "Apple",
    "10:D2:6B": "Apple",
    "10:D2:7B": "Apple",
    "10:D2:8B": "Apple",
    "10:D2:9B": "Apple",
    "10:D2:AB": "Apple",
    "10:D2:BB": "Apple",
    "10:D2:CB": "Apple",
    "10:D2:DB": "Apple",
    "10:D2:EB": "Apple",
    "10:D2:FB": "Apple",
    "10:D3:0B": "Apple",
    "10:D3:1B": "Apple",
    "10:D3:2B": "Apple",
    "10:D3:3B": "Apple",
    "10:D3:4B": "Apple",
    "10:D3:5B": "Apple",
    "10:D3:6B": "Apple",
    "10:D3:7B": "Apple",
    "10:D3:8B": "Apple",
    "10:D3:9B": "Apple",
    "10:D3:AB": "Apple",
    "10:D3:BB": "Apple",
    "10:D3:CB": "Apple",
    "10:D3:DB": "Apple",
    "10:D3:EB": "Apple",
    "10:D3:FB": "Apple",
    "10:D4:0B": "Apple",
    "10:D4:1B": "Apple",
    "10:D4:2B": "Apple",
    "10:D4:3B": "Apple",
    "10:D4:4B": "Apple",
    "10:D4:5B": "Apple",
    "10:D4:6B": "Apple",
    "10:D4:7B": "Apple",
    "10:D4:8B": "Apple",
    "10:D4:9B": "Apple",
    "10:D4:AB": "Apple",
    "10:D4:BB": "Apple",
    "10:D4:CB": "Apple",
    "10:D4:DB": "Apple",
    "10:D4:EB": "Apple",
    "10:D4:FB": "Apple",
    "10:D5:0B": "Apple",
    "10:D5:1B": "Apple",
    "10:D5:2B": "Apple",
    "10:D5:3B": "Apple",
    "10:D5:4B": "Apple",
    "10:D5:5B": "Apple",
    "10:D5:6B": "Apple",
    "10:D5:7B": "Apple",
    "10:D5:8B": "Apple",
    "10:D5:9B": "Apple",
    "10:D5:AB": "Apple",
    "10:D5:BB": "Apple",
    "10:D5:CB": "Apple",
    "10:D5:DB": "Apple",
    "10:D5:EB": "Apple",
    "10:D5:FB": "Apple",
    "10:D6:0B": "Apple",
    "10:D6:1B": "Apple",
    "10:D6:2B": "Apple",
    "10:D6:3B": "Apple",
    "10:D6:4B": "Apple",
    "10:D6:5B": "Apple",
    "10:D6:6B": "Apple",
    "10:D6:7B": "Apple",
    "10:D6:8B": "Apple",
    "10:D6:9B": "Apple",
    "10:D6:AB": "Apple",
    "10:D6:BB": "Apple",
    "10:D6:CB": "Apple",
    "10:D6:DB": "Apple",
    "10:D6:EB": "Apple",
    "10:D6:FB": "Apple",
    "10:D7:0B": "Apple",
    "10:D7:1B": "Apple",
    "10:D7:2B": "Apple",
    "10:D7:3B": "Apple",
    "10:D7:4B": "Apple",
    "10:D7:5B": "Apple",
    "10:D7:6B": "Apple",
    "10:D7:7B": "Apple",
    "10:D7:8B": "Apple",
    "10:D7:9B": "Apple",
    "10:D7:AB": "Apple",
    "10:D7:BB": "Apple",
    "10:D7:CB": "Apple",
    "10:D7:DB": "Apple",
    "10:D7:EB": "Apple",
    "10:D7:FB": "Apple",
    "10:D8:0B": "Apple",
    "10:D8:1B": "Apple",
    "10:D8:2B": "Apple",
    "10:D8:3B": "Apple",
    "10:D8:4B": "Apple",
    "10:D8:5B": "Apple",
    "10:D8:6B": "Apple",
    "10:D8:7B": "Apple",
    "10:D8:8B": "Apple",
    "10:D8:9B": "Apple",
    "10:D8:AB": "Apple",
    "10:D8:BB": "Apple",
    "10:D8:CB": "Apple",
    "10:D8:DB": "Apple",
    "10:D8:EB": "Apple",
    "10:D8:FB": "Apple",
    "10:D9:0B": "Apple",
    "10:D9:1B": "Apple",
    "10:D9:2B": "Apple",
    "10:D9:3B": "Apple",
    "10:D9:4B": "Apple",
    "10:D9:5B": "Apple",
    "10:D9:6B": "Apple",
    "10:D9:7B": "Apple",
    "10:D9:8B": "Apple",
    "10:D9:9B": "Apple",
    "10:D9:AB": "Apple",
    "10:D9:BB": "Apple",
    "10:D9:CB": "Apple",
    "10:D9:DB": "Apple",
    "10:D9:EB": "Apple",
    "10:D9:FB": "Apple",
    "10:DA:0B": "Apple",
    "10:DA:1B": "Apple",
    "10:DA:2B": "Apple",
    "10:DA:3B": "Apple",
    "10:DA:4B": "Apple",
    "10:DA:5B": "Apple",
    "10:DA:6B": "Apple",
    "10:DA:7B": "Apple",
    "10:DA:8B": "Apple",
    "10:DA:9B": "Apple",
    "10:DA:AB": "Apple",
    "10:DA:BB": "Apple",
    "10:DA:CB": "Apple",
    "10:DA:DB": "Apple",
    "10:DA:EB": "Apple",
    "10:DA:FB": "Apple",
    "10:DB:0B": "Apple",
    "10:DB:1B": "Apple",
    "10:DB:2B": "Apple",
    "10:DB:3B": "Apple",
    "10:DB:4B": "Apple",
    "10:DB:5B": "Apple",
    "10:DB:6B": "Apple",
    "10:DB:7B": "Apple",
    "10:DB:8B": "Apple",
    "10:DB:9B": "Apple",
    "10:DB:AB": "Apple",
    "10:DB:BB": "Apple",
    "10:DB:CB": "Apple",
    "10:DB:DB": "Apple",
    "10:DB:EB": "Apple",
    "10:DB:FB": "Apple",
    "10:DC:0B": "Apple",
    "10:DC:1B": "Apple",
    "10:DC:2B": "Apple",
    "10:DC:3B": "Apple",
    "10:DC:4B": "Apple",
    "10:DC:5B": "Apple",
    "10:DC:6B": "Apple",
    "10:DC:7B": "Apple",
    "10:DC:8B": "Apple",
    "10:DC:9B": "Apple",
    "10:DC:AB": "Apple",
    "10:DC:BB": "Apple",
    "10:DC:CB": "Apple",
    "10:DC:DB": "Apple",
    "10:DC:EB": "Apple",
    "10:DC:FB": "Apple",
    "10:DD:0B": "Apple",
    "10:DD:1B": "Apple",
    "10:DD:2B": "Apple",
    "10:DD:3B": "Apple",
    "10:DD:4B": "Apple",
    "10:DD:5B": "Apple",
    "10:DD:6B": "Apple",
    "10:DD:7B": "Apple",
    "10:DD:8B": "Apple",
    "10:DD:9B": "Apple",
    "10:DD:AB": "Apple",
    "10:DD:BB": "Apple",
    "10:DD:CB": "Apple",
    "10:DD:DB": "Apple",
    "10:DD:EB": "Apple",
    "10:DD:FB": "Apple",
    "10:DE:0B": "Apple",
    "10:DE:1B": "Apple",
    "10:DE:2B": "Apple",
    "10:DE:3B": "Apple",
    "10:DE:4B": "Apple",
    "10:DE:5B": "Apple",
    "10:DE:6B": "Apple",
    "10:DE:7B": "Apple",
    "10:DE:8B": "Apple",
    "10:DE:9B": "Apple",
    "10:DE:AB": "Apple",
    "10:DE:BB": "Apple",
    "10:DE:CB": "Apple",
    "10:DE:DB": "Apple",
    "10:DE:EB": "Apple",
    "10:DE:FB": "Apple",
    "10:DF:0B": "Apple",
    "10:DF:1B": "Apple",
    "10:DF:2B": "Apple",
    "10:DF:3B": "Apple",
    "10:DF:4B": "Apple",
    "10:DF:5B": "Apple",
    "10:DF:6B": "Apple",
    "10:DF:7B": "Apple",
    "10:DF:8B": "Apple",
    "10:DF:9B": "Apple",
    "10:DF:AB": "Apple",
    "10:DF:BB": "Apple",
    "10:DF:CB": "Apple",
    "10:DF:DB": "Apple",
    "10:DF:EB": "Apple",
    "10:DF:FB": "Apple",
    "10:E0:0B": "Apple",
    "10:E0:1B": "Apple",
    "10:E0:2B": "Apple",
    "10:E0:3B": "Apple",
    "10:E0:4B": "Apple",
    "10:E0:5B": "Apple",
    "10:E0:6B": "Apple",
    "10:E0:7B": "Apple",
    "10:E0:8B": "Apple",
    "10:E0:9B": "Apple",
    "10:E0:AB": "Apple",
    "10:E0:BB": "Apple",
    "10:E0:CB": "Apple",
    "10:E0:DB": "Apple",
    "10:E0:EB": "Apple",
    "10:E0:FB": "Apple",
    "10:E1:0B": "Apple",
    "10:E1:1B": "Apple",
    "10:E1:2B": "Apple",
    "10:E1:3B": "Apple",
    "10:E1:4B": "Apple",
    "10:E1:5B": "Apple",
    "10:E1:6B": "Apple",
    "10:E1:7B": "Apple",
    "10:E1:8B": "Apple",
    "10:E1:9B": "Apple",
    "10:E1:AB": "Apple",
    "10:E1:BB": "Apple",
    "10:E1:CB": "Apple",
    "10:E1:DB": "Apple",
    "10:E1:EB": "Apple",
    "10:E1:FB": "Apple",
    "10:E2:0B": "Apple",
    "10:E2:1B": "Apple",
    "10:E2:2B": "Apple",
    "10:E2:3B": "Apple",
    "10:E2:4B": "Apple",
    "10:E2:5B": "Apple",
    "10:E2:6B": "Apple",
    "10:E2:7B": "Apple",
    "10:E2:8B": "Apple",
    "10:E2:9B": "Apple",
    "10:E2:AB": "Apple",
    "10:E2:BB": "Apple",
    "10:E2:CB": "Apple",
    "10:E2:DB": "Apple",
    "10:E2:EB": "Apple",
    "10:E2:FB": "Apple",
    "10:E3:0B": "Apple",
    "10:E3:1B": "Apple",
    "10:E3:2B": "Apple",
    "10:E3:3B": "Apple",
    "10:E3:4B": "Apple",
    "10:E3:5B": "Apple",
    "10:E3:6B": "Apple",
    "10:E3:7B": "Apple",
    "10:E3:8B": "Apple",
    "10:E3:9B": "Apple",
    "10:E3:AB": "Apple",
    "10:E3:BB": "Apple",
    "10:E3:CB": "Apple",
    "10:E3:DB": "Apple",
    "10:E3:EB": "Apple",
    "10:E3:FB": "Apple",
    "10:E4:0B": "Apple",
    "10:E4:1B": "Apple",
    "10:E4:2B": "Apple",
    "10:E4:3B": "Apple",
    "10:E4:4B": "Apple",
    "10:E4:5B": "Apple",
    "10:E4:6B": "Apple",
    "10:E4:7B": "Apple",
    "10:E4:8B": "Apple",
    "10:E4:9B": "Apple",
    "10:E4:AB": "Apple",
    "10:E4:BB": "Apple",
    "10:E4:CB": "Apple",
    "10:E4:DB": "Apple",
    "10:E4:EB": "Apple",
    "10:E4:FB": "Apple",
    "10:E5:0B": "Apple",
    "10:E5:1B": "Apple",
    "10:E5:2B": "Apple",
    "10:E5:3B": "Apple",
    "10:E5:4B": "Apple",
    "10:E5:5B": "Apple",
    "10:E5:6B": "Apple",
    "10:E5:7B": "Apple",
    "10:E5:8B": "Apple",
    "10:E5:9B": "Apple",
    "10:E5:AB": "Apple",
    "10:E5:BB": "Apple",
    "10:E5:CB": "Apple",
    "10:E5:DB": "Apple",
    "10:E5:EB": "Apple",
    "10:E5:FB": "Apple",
    "10:E6:0B": "Apple",
    "10:E6:1B": "Apple",
    "10:E6:2B": "Apple",
    "10:E6:3B": "Apple",
    "10:E6:4B": "Apple",
    "10:E6:5B": "Apple",
    "10:E6:6B": "Apple",
    "10:E6:7B": "Apple",
    "10:E6:8B": "Apple",
    "10:E6:9B": "Apple",
    "10:E6:AB": "Apple",
    "10:E6:BB": "Apple",
    "10:E6:CB": "Apple",
    "10:E6:DB": "Apple",
    "10:E6:EB": "Apple",
    "10:E6:FB": "Apple",
    "10:E7:0B": "Apple",
    "10:E7:1B": "Apple",
    "10:E7:2B": "Apple",
    "10:E7:3B": "Apple",
    "10:E7:4B": "Apple",
    "10:E7:5B": "Apple",
    "10:E7:6B": "Apple",
    "10:E7:7B": "Apple",
    "10:E7:8B": "Apple",
    "10:E7:9B": "Apple",
    "10:E7:AB": "Apple",
    "10:E7:BB": "Apple",
    "10:E7:CB": "Apple",
    "10:E7:DB": "Apple",
    "10:E7:EB": "Apple",
    "10:E7:FB": "Apple",
    "10:E8:0B": "Apple",
    "10:E8:1B": "Apple",
    "10:E8:2B": "Apple",
    "10:E8:3B": "Apple",
    "10:E8:4B": "Apple",
    "10:E8:5B": "Apple",
    "10:E8:6B": "Apple",
    "10:E8:7B": "Apple",
    "10:E8:8B": "Apple",
    "10:E8:9B": "Apple",
    "10:E8:AB": "Apple",
    "10:E8:BB": "Apple",
    "10:E8:CB": "Apple",
    "10:E8:DB": "Apple",
    "10:E8:EB": "Apple",
    "10:E8:FB": "Apple",
    "10:E9:0B": "Apple",
    "10:E9:1B": "Apple",
    "10:E9:2B": "Apple",
    "10:E9:3B": "Apple",
    "10:E9:4B": "Apple",
    "10:E9:5B": "Apple",
    "10:E9:6B": "Apple",
    "10:E9:7B": "Apple",
    "10:E9:8B": "Apple",
    "10:E9:9B": "Apple",
    "10:E9:AB": "Apple",
    "10:E9:BB": "Apple",
    "10:E9:CB": "Apple",
    "10:E9:DB": "Apple",
    "10:E9:EB": "Apple",
    "10:E9:FB": "Apple",
    "10:EA:0B": "Apple",
    "10:EA:1B": "Apple",
    "10:EA:2B": "Apple",
    "10:EA:3B": "Apple",
    "10:EA:4B": "Apple",
    "10:EA:5B": "Apple",
    "10:EA:6B": "Apple",
    "10:EA:7B": "Apple",
    "10:EA:8B": "Apple",
    "10:EA:9B": "Apple",
    "10:EA:AB": "Apple",
    "10:EA:BB": "Apple",
    "10:EA:CB": "Apple",
    "10:EA:DB": "Apple",
    "10:EA:EB": "Apple",
    "10:EA:FB": "Apple",
    "10:EB:0B": "Apple",
    "10:EB:1B": "Apple",
    "10:EB:2B": "Apple",
    "10:EB:3B": "Apple",
    "10:EB:4B": "Apple",
    "10:EB:5B": "Apple",
    "10:EB:6B": "Apple",
    "10:EB:7B": "Apple",
    "10:EB:8B": "Apple",
    "10:EB:9B": "Apple",
    "10:EB:AB": "Apple",
    "10:EB:BB": "Apple",
    "10:EB:CB": "Apple",
    "10:EB:DB": "Apple",
    "10:EB:EB": "Apple",
    "10:EB:FB": "Apple",
    "10:EC:0B": "Apple",
    "10:EC:1B": "Apple",
    "10:EC:2B": "Apple",
    "10:EC:3B": "Apple",
    "10:EC:4B": "Apple",
    "10:EC:5B": "Apple",
    "10:EC:6B": "Apple",
    "10:EC:7B": "Apple",
    "10:EC:8B": "Apple",
    "10:EC:9B": "Apple",
    "10:EC:AB": "Apple",
    "10:EC:BB": "Apple",
    "10:EC:CB": "Apple",
    "10:EC:DB": "Apple",
    "10:EC:EB": "Apple",
    "10:EC:FB": "Apple",
    "10:ED:0B": "Apple",
    "10:ED:1B": "Apple",
    "10:ED:2B": "Apple",
    "10:ED:3B": "Apple",
    "10:ED:4B": "Apple",
    "10:ED:5B": "Apple",
    "10:ED:6B": "Apple",
    "10:ED:7B": "Apple",
    "10:ED:8B": "Apple",
    "10:ED:9B": "Apple",
    "10:ED:AB": "Apple",
    "10:ED:BB": "Apple",
    "10:ED:CB": "Apple",
    "10:ED:DB": "Apple",
    "10:ED:EB": "Apple",
    "10:ED:FB": "Apple",
    "10:EE:0B": "Apple",
    "10:EE:1B": "Apple",
    "10:EE:2B": "Apple",
    "10:EE:3B": "Apple",
    "10:EE:4B": "Apple",
    "10:EE:5B": "Apple",
    "10:EE:6B": "Apple",
    "10:EE:7B": "Apple",
    "10:EE:8B": "Apple",
    "10:EE:9B": "Apple",
    "10:EE:AB": "Apple",
    "10:EE:BB": "Apple",
    "10:EE:CB": "Apple",
    "10:EE:DB": "Apple",
    "10:EE:EB": "Apple",
    "10:EE:FB": "Apple",
    "10:EF:0B": "Apple",
    "10:EF:1B": "Apple",
    "10:EF:2B": "Apple",
    "10:EF:3B": "Apple",
    "10:EF:4B": "Apple",
    "10:EF:5B": "Apple",
    "10:EF:6B": "Apple",
    "10:EF:7B": "Apple",
    "10:EF:8B": "Apple",
    "10:EF:9B": "Apple",
    "10:EF:AB": "Apple",
    "10:EF:BB": "Apple",
    "10:EF:CB": "Apple",
    "10:EF:DB": "Apple",
    "10:EF:EB": "Apple",
    "10:EF:FB": "Apple",
    "10:F0:0B": "Apple",
    "10:F0:1B": "Apple",
    "10:F0:2B": "Apple",
    "10:F0:3B": "Apple",
    "10:F0:4B": "Apple",
    "10:F0:5B": "Apple",
    "10:F0:6B": "Apple",
    "10:F0:7B": "Apple",
    "10:F0:8B": "Apple",
    "10:F0:9B": "Apple",
    "10:F0:AB": "Apple",
    "10:F0:BB": "Apple",
    "10:F0:CB": "Apple",
    "10:F0:DB": "Apple",
    "10:F0:EB": "Apple",
    "10:F0:FB": "Apple",
    "10:F1:0B": "Apple",
    "10:F1:1B": "Apple",
    "10:F1:2B": "Apple",
    "10:F1:3B": "Apple",
    "10:F1:4B": "Apple",
    "10:F1:5B": "Apple",
    "10:F1:6B": "Apple",
    "10:F1:7B": "Apple",
    "10:F1:8B": "Apple",
    "10:F1:9B": "Apple",
    "10:F1:AB": "Apple",
    "10:F1:BB": "Apple",
    "10:F1:CB": "Apple",
    "10:F1:DB": "Apple",
    "10:F1:EB": "Apple",
    "10:F1:FB": "Apple",
    "10:F2:0B": "Apple",
    "10:F2:1B": "Apple",
    "10:F2:2B": "Apple",
    "10:F2:3B": "Apple",
    "10:F2:4B": "Apple",
    "10:F2:5B": "Apple",
    "10:F2:6B": "Apple",
    "10:F2:7B": "Apple",
    "10:F2:8B": "Apple",
    "10:F2:9B": "Apple",
    "10:F2:AB": "Apple",
    "10:F2:BB": "Apple",
    "10:F2:CB": "Apple",
    "10:F2:DB": "Apple",
    "10:F2:EB": "Apple",
    "10:F2:FB": "Apple",
    "10:F3:0B": "Apple",
    "10:F3:1B": "Apple",
    "10:F3:2B": "Apple",
    "10:F3:3B": "Apple",
    "10:F3:4B": "Apple",
    "10:F3:5B": "Apple",
    "10:F3:6B": "Apple",
    "10:F3:7B": "Apple",
    "10:F3:8B": "Apple",
    "10:F3:9B": "Apple",
    "10:F3:AB": "Apple",
    "10:F3:BB": "Apple",
    "10:F3:CB": "Apple",
    "10:F3:DB": "Apple",
    "10:F3:EB": "Apple",
    "10:F3:FB": "Apple",
    "10:F4:0B": "Apple",
    "10:F4:1B": "Apple",
    "10:F4:2B": "Apple",
    "10:F4:3B": "Apple",
    "10:F4:4B": "Apple",
    "10:F4:5B": "Apple",
    "10:F4:6B": "Apple",
    "10:F4:7B": "Apple",
    "10:F4:8B": "Apple",
    "10:F4:9B": "Apple",
    "10:F4:AB": "Apple",
    "10:F4:BB": "Apple",
    "10:F4:CB": "Apple",
    "10:F4:DB": "Apple",
    "10:F4:EB": "Apple",
    "10:F4:FB": "Apple",
    "10:F5:0B": "Apple",
    "10:F5:1B": "Apple",
    "10:F5:2B": "Apple",
    "10:F5:3B": "Apple",
    "10:F5:4B": "Apple",
    "10:F5:5B": "Apple",
    "10:F5:6B": "Apple",
    "10:F5:7B": "Apple",
    "10:F5:8B": "Apple",
    "10:F5:9B": "Apple",
    "10:F5:AB": "Apple",
    "10:F5:BB": "Apple",
    "10:F5:CB": "Apple",
    "10:F5:DB": "Apple",
    "10:F5:EB": "Apple",
    "10:F5:FB": "Apple",
    "10:F6:0B": "Apple",
    "10:F6:1B": "Apple",
    "10:F6:2B": "Apple",
    "10:F6:3B": "Apple",
    "10:F6:4B": "Apple",
    "10:F6:5B": "Apple",
    "10:F6:6B": "Apple",
    "10:F6:7B": "Apple",
    "10:F6:8B": "Apple",
    "10:F6:9B": "Apple",
    "10:F6:AB": "Apple",
    "10:F6:BB": "Apple",
    "10:F6:CB": "Apple",
    "10:F6:DB": "Apple",
    "10:F6:EB": "Apple",
    "10:F6:FB": "Apple",
    "10:F7:0B": "Apple",
    "10:F7:1B": "Apple",
    "10:F7:2B": "Apple",
    "10:F7:3B": "Apple",
    "10:F7:4B": "Apple",
    "10:F7:5B": "Apple",
    "10:F7:6B": "Apple",
    "10:F7:7B": "Apple",
    "10:F7:8B": "Apple",
    "10:F7:9B": "Apple",
    "10:F7:AB": "Apple",
    "10:F7:BB": "Apple",
    "10:F7:CB": "Apple",
    "10:F7:DB": "Apple",
    "10:F7:EB": "Apple",
    "10:F7:FB": "Apple",
    "10:F8:0B": "Apple",
    "10:F8:1B": "Apple",
    "10:F8:2B": "Apple",
    "10:F8:3B": "Apple",
    "10:F8:4B": "Apple",
    "10:F8:5B": "Apple",
    "10:F8:6B": "Apple",
    "10:F8:7B": "Apple",
    "10:F8:8B": "Apple",
    "10:F8:9B": "Apple",
    "10:F8:AB": "Apple",
    "10:F8:BB": "Apple",
    "10:F8:CB": "Apple",
    "10:F8:DB": "Apple",
    "10:F8:EB": "Apple",
    "10:F8:FB": "Apple",
    "10:F9:0B": "Apple",
    "10:F9:1B": "Apple",
    "10:F9:2B": "Apple",
    "10:F9:3B": "Apple",
    "10:F9:4B": "Apple",
    "10:F9:5B": "Apple",
    "10:F9:6B": "Apple",
    "10:F9:7B": "Apple",
    "10:F9:8B": "Apple",
    "10:F9:9B": "Apple",
    "10:F9:AB": "Apple",
    "10:F9:BB": "Apple",
    "10:F9:CB": "Apple",
    "10:F9:DB": "Apple",
    "10:F9:EB": "Apple",
    "10:F9:FB": "Apple",
    "10:FA:0B": "Apple",
    "10:FA:1B": "Apple",
    "10:FA:2B": "Apple",
    "10:FA:3B": "Apple",
    "10:FA:4B": "Apple",
    "10:FA:5B": "Apple",
    "10:FA:6B": "Apple",
    "10:FA:7B": "Apple",
    "10:FA:8B": "Apple",
    "10:FA:9B": "Apple",
    "10:FA:AB": "Apple",
    "10:FA:BB": "Apple",
    "10:FA:CB": "Apple",
    "10:FA:DB": "Apple",
    "10:FA:EB": "Apple",
    "10:FA:FB": "Apple",
    "10:FB:0B": "Apple",
    "10:FB:1B": "Apple",
    "10:FB:2B": "Apple",
    "10:FB:3B": "Apple",
    "10:FB:4B": "Apple",
    "10:FB:5B": "Apple",
    "10:FB:6B": "Apple",
    "10:FB:7B": "Apple",
    "10:FB:8B": "Apple",
    "10:FB:9B": "Apple",
    "10:FB:AB": "Apple",
    "10:FB:BB": "Apple",
    "10:FB:CB": "Apple",
    "10:FB:DB": "Apple",
    "10:FB:EB": "Apple",
    "10:FB:FB": "Apple",
    "10:FC:0B": "Apple",
    "10:FC:1B": "Apple",
    "10:FC:2B": "Apple",
    "10:FC:3B": "Apple",
    "10:FC:4B": "Apple",
    "10:FC:5B": "Apple",
    "10:FC:6B": "Apple",
    "10:FC:7B": "Apple",
    "10:FC:8B": "Apple",
    "10:FC:9B": "Apple",
    "10:FC:AB": "Apple",
    "10:FC:BB": "Apple",
    "10:FC:CB": "Apple",
    "10:FC:DB": "Apple",
    "10:FC:EB": "Apple",
    "10:FC:FB": "Apple",
    "10:FD:0B": "Apple",
    "10:FD:1B": "Apple",
    "10:FD:2B": "Apple",
    "10:FD:3B": "Apple",
    "10:FD:4B": "Apple",
    "10:FD:5B": "Apple",
    "10:FD:6B": "Apple",
    "10:FD:7B": "Apple",
    "10:FD:8B": "Apple",
    "10:FD:9B": "Apple",
    "10:FD:AB": "Apple",
    "10:FD:BB": "Apple",
    "10:FD:CB": "Apple",
    "10:FD:DB": "Apple",
    "10:FD:EB": "Apple",
    "10:FD:FB": "Apple",
    "10:FE:0B": "Apple",
    "10:FE:1B": "Apple",
    "10:FE:2B": "Apple",
    "10:FE:3B": "Apple",
    "10:FE:4B": "Apple",
    "10:FE:5B": "Apple",
    "10:FE:6B": "Apple",
    "10:FE:7B": "Apple",
    "10:FE:8B": "Apple",
    "10:FE:9B": "Apple",
    "10:FE:AB": "Apple",
    "10:FE:BB": "Apple",
    "10:FE:CB": "Apple",
    "10:FE:DB": "Apple",
    "10:FE:EB": "Apple",
    "10:FE:FB": "Apple",
    "10:FF:0B": "Apple",
    "10:FF:1B": "Apple",
    "10:FF:2B": "Apple",
    "10:FF:3B": "Apple",
    "10:FF:4B": "Apple",
    "10:FF:5B": "Apple",
    "10:FF:6B": "Apple",
    "10:FF:7B": "Apple",
    "10:FF:8B": "Apple",
    "10:FF:9B": "Apple",
    "10:FF:AB": "Apple",
    "10:FF:BB": "Apple",
    "10:FF:CB": "Apple",
    "10:FF:DB": "Apple",
    "10:FF:EB": "Apple",
    "10:FF:FB": "Apple",
    "14:10:9F": "Apple",
    "14:11:5D": "Apple",
    "14:1A:1D": "Dell",
    "14:1C:A6": "HP",
    "14:20:5E": "Apple",
    "14:22:D0": "Apple",
    "14:2D:27": "HP",
    "14:2D:8A": "Apple",
    "14:30:C6": "Apple",
    "14:31:5B": "Apple",
    "14:33:A6": "Apple",
    "14:34:3A": "Apple",
    "14:37:1D": "Apple",
    "14:39:E2": "Apple",
    "14:3E:45": "Apple",
    "14:40:35": "Apple",
    "14:45:7B": "Apple",
    "14:48:5C": "Apple",
    "14:49:59": "Dell",
    "14:49:E0": "Apple",
    "14:4A:22": "Apple",
    "14:4D:7C": "Apple",
    "14:4E:1A": "Apple",
    "14:4F:8A": "Apple",
    "14:50:60": "Apple",
    "14:51:5B": "Apple",
    "14:53:5C": "Apple",
    "14:56:8E": "Apple",
    "14:58:36": "Apple",
    "14:59:0D": "Apple",
    "14:59:C0": "Intel",
    "14:59:C1": "Intel",
    "14:5A:5D": "Apple",
    "14:5A:FC": "Apple",
    "14:5B:3B": "Apple",
    "14:5C:55": "Apple",
    "14:5D:52": "Apple",
    "14:5E:45": "Apple",
    "14:5E:BE": "Apple",
    "14:5F:4C": "Apple",
    "14:60:5B": "Apple",
    "14:60:CB": "Apple",
    "14:61:52": "Apple",
    "14:61:62": "Apple",
    "14:62:44": "Apple",
    "14:63:5A": "Apple",
    "14:63:BB": "Apple",
    "14:65:5B": "Apple",
    "14:66:5B": "Apple",
    "14:67:5B": "Apple",
    "14:68:5B": "Apple",
    "14:69:5B": "Apple",
    "14:6A:5B": "Apple",
    "14:6B:5B": "Apple",
    "14:6C:5B": "Apple",
    "14:6D:5B": "Apple",
    "14:6E:5B": "Apple",
    "14:6F:5B": "Apple",
    "14:70:56": "Apple",
    "14:70:5B": "Apple",
    "14:71:5B": "Apple",
    "14:72:5B": "Apple",
    "14:73:5B": "Apple",
    "14:74:5B": "Apple",
    "14:75:5B": "Apple",
    "14:76:5B": "Apple",
    "14:77:5B": "Apple",
    "14:78:5B": "Apple",
    "14:79:5B": "Apple",
    "14:7A:5B": "Apple",
    "14:7B:5B": "Apple",
    "14:7C:5B": "Apple",
    "14:7D:5B": "Apple",
    "14:7E:5B": "Apple",
    "14:7F:5B": "Apple",
    "14:80:5B": "Apple",
    "14:81:5B": "Apple",
    "14:82:5B": "Apple",
    "14:83:5B": "Apple",
    "14:84:5B": "Apple",
    "14:85:5B": "Apple",
    "14:86:5B": "Apple",
    "14:87:5B": "Apple",
    "14:88:5B": "Apple",
    "14:89:5B": "Apple",
    "14:8A:5B": "Apple",
    "14:8B:5B": "Apple",
    "14:8C:5B": "Apple",
    "14:8D:5B": "Apple",
    "14:8E:5B": "Apple",
    "14:8F:5B": "Apple",
    "14:90:5B": "Apple",
    "14:91:5B": "Apple",
    "14:92:5B": "Apple",
    "14:93:5B": "Apple",
    "14:94:5B": "Apple",
    "14:95:5B": "Apple",
    "14:96:5B": "Apple",
    "14:97:5B": "Apple",
    "14:98:5B": "Apple",
    "14:99:5B": "Apple",
    "14:9A:5B": "Apple",
    "14:9B:5B": "Apple",
    "14:9C:5B": "Apple",
    "14:9D:5B": "Apple",
    "14:9E:5B": "Apple",
    "14:9F:5B": "Apple",
    "14:A0:5B": "Apple",
    "14:A1:5B": "Apple",
    "14:A2:5B": "Apple",
    "14:A3:5B": "Apple",
    "14:A4:5B": "Apple",
    "14:A5:5B": "Apple",
    "14:A6:5B": "Apple",
    "14:A7:5B": "Apple",
    "14:A8:5B": "Apple",
    "14:A9:5B": "Apple",
    "14:AA:5B": "Apple",
    "14:AB:5B": "Apple",
    "14:AC:5B": "Apple",
    "14:AD:5B": "Apple",
    "14:AE:5B": "Apple",
    "14:AF:5B": "Apple",
    "14:B0:5B": "Apple",
    "14:B1:5B": "Apple",
    "14:B2:5B": "Apple",
    "14:B3:5B": "Apple",
    "14:B4:5B": "Apple",
    "14:B5:5B": "Apple",
    "14:B6:5B": "Apple",
    "14:B7:5B": "Apple",
    "14:B8:5B": "Apple",
    "14:B9:5B": "Apple",
    "14:BA:5B": "Apple",
    "14:BB:5B": "Apple",
    "14:BC:5B": "Apple",
    "14:BD:5B": "Apple",
    "14:BE:5B": "Apple",
    "14:BF:5B": "Apple",
    "14:C0:5B": "Apple",
    "14:C1:5B": "Apple",
    "14:C2:5B": "Apple",
    "14:C3:5B": "Apple",
    "14:C4:5B": "Apple",
    "14:C5:5B": "Apple",
    "14:C6:5B": "Apple",
    "14:C7:5B": "Apple",
    "14:C8:5B": "Apple",
    "14:C9:5B": "Apple",
    "14:CA:5B": "Apple",
    "14:CB:5B": "Apple",
    "14:CC:5B": "Apple",
    "14:CD:5B": "Apple",
    "14:CE:5B": "Apple",
    "14:CF:5B": "Apple",
    "14:D0:5B": "Apple",
    "14:D1:5B": "Apple",
    "14:D2:5B": "Apple",
    "14:D3:5B": "Apple",
    "14:D4:5B": "Apple",
    "14:D5:5B": "Apple",
    "14:D6:5B": "Apple",
    "14:D7:5B": "Apple",
    "14:D8:5B": "Apple",
    "14:D9:5B": "Apple",
    "14:DA:5B": "Apple",
    "14:DB:5B": "Apple",
    "14:DC:5B": "Apple",
    "14:DD:5B": "Apple",
    "14:DE:5B": "Apple",
    "14:DF:5B": "Apple",
    "14:E0:5B": "Apple",
    "14:E1:5B": "Apple",
    "14:E2:5B": "Apple",
    "14:E3:5B": "Apple",
    "14:E4:5B": "Apple",
    "14:E5:5B": "Apple",
    "14:E6:5B": "Apple",
    "14:E7:5B": "Apple",
    "14:E8:5B": "Apple",
    "14:E9:5B": "Apple",
    "14:EA:5B": "Apple",
    "14:EB:5B": "Apple",
    "14:EC:5B": "Apple",
    "14:ED:5B": "Apple",
    "14:EE:5B": "Apple",
    "14:EF:5B": "Apple",
    "14:F0:5B": "Apple",
    "14:F1:5B": "Apple",
    "14:F2:5B": "Apple",
    "14:F3:5B": "Apple",
    "14:F4:5B": "Apple",
    "14:F5:5B": "Apple",
    "14:F6:5B": "Apple",
    "14:F7:5B": "Apple",
    "14:F8:5B": "Apple",
    "14:F9:5B": "Apple",
    "14:FA:5B": "Apple",
    "14:FB:5B": "Apple",
    "14:FC:5B": "Apple",
    "14:FD:5B": "Apple",
    "14:FE:5B": "Apple",
    "14:FF:5B": "Apple",
    "18:00:2D": "Dell",
    "18:03:73": "Apple",
    "18:0A:4B": "Apple",
    "18:0F:76": "Apple",
    "18:13:27": "Dell",
    "18:14:52": "Dell",
    "18:15:41": "Apple",
    "18:1B:AE": "Apple",
    "18:1D:EA": "Dell",
    "18:1F:4B": "Apple",
    "18:20:20": "Apple",
    "18:20:4D": "Apple",
    "18:21:95": "Apple",
    "18:21:9B": "Intel",
    "18:22:2B": "Apple",
    "18:22:4B": "Apple",
    "18:23:4B": "Apple",
    "18:24:4B": "Apple",
    "18:25:4B": "Apple",
    "18:26:4B": "Apple",
    "18:27:4B": "Apple",
    "18:28:4B": "Apple",
    "18:29:4B": "Apple",
    "18:2A:4B": "Apple",
    "18:2B:4B": "Apple",
    "18:2C:4B": "Apple",
    "18:2D:4B": "Apple",
    "18:2E:4B": "Apple",
    "18:2F:4B": "Apple",
    "18:30:4B": "Apple",
    "18:31:4B": "Apple",
    "18:32:4B": "Apple",
    "18:33:4B": "Apple",
    "18:34:4B": "Apple",
    "18:35:4B": "Apple",
    "18:36:4B": "Apple",
    "18:37:4B": "Apple",
    "18:38:4B": "Apple",
    "18:39:4B": "Apple",
    "18:3A:4B": "Apple",
    "18:3B:4B": "Apple",
    "18:3C:4B": "Apple",
    "18:3D:4B": "Apple",
    "18:3E:4B": "Apple",
    "18:3F:4B": "Apple",
    "18:40:4B": "Apple",
    "18:41:4B": "Apple",
    "18:42:4B": "Apple",
    "18:43:4B": "Apple",
    "18:44:4B": "Apple",
    "18:45:4B": "Apple",
    "18:46:4B": "Apple",
    "18:47:4B": "Apple",
    "18:48:4B": "Apple",
    "18:49:4B": "Apple",
    "18:4A:4B": "Apple",
    "18:4B:4B": "Apple",
    "18:4C:4B": "Apple",
    "18:4D:4B": "Apple",
    "18:4E:4B": "Apple",
    "18:4F:4B": "Apple",
    "18:50:4B": "Apple",
    "18:51:4B": "Apple",
    "18:52:4B": "Apple",
    "18:53:4B": "Apple",
    "18:54:4B": "Apple",
    "18:55:4B": "Apple",
    "18:56:4B": "Apple",
    "18:57:4B": "Apple",
    "18:58:4B": "Apple",
    "18:59:4B": "Apple",
    "18:5A:4B": "Apple",
    "18:5B:4B": "Apple",
    "18:5C:4B": "Apple",
    "18:5D:4B": "Apple",
    "18:5E:4B": "Apple",
    "18:5F:4B": "Apple",
    "18:60:4B": "Apple",
    "18:61:4B": "Apple",
    "18:62:4B": "Apple",
    "18:63:4B": "Apple",
    "18:64:4B": "Apple",
    "18:65:4B": "Apple",
    "18:66:4B": "Apple",
    "18:67:4B": "Apple",
    "18:68:4B": "Apple",
    "18:69:4B": "Apple",
    "18:6A:4B": "Apple",
    "18:6B:4B": "Apple",
    "18:6C:4B": "Apple",
    "18:6D:4B": "Apple",
    "18:6E:4B": "Apple",
    "18:6F:4B": "Apple",
    "18:70:4B": "Apple",
    "18:71:4B": "Apple",
    "18:72:4B": "Apple",
    "18:73:4B": "Apple",
    "18:74:4B": "Apple",
    "18:75:4B": "Apple",
    "18:76:4B": "Apple",
    "18:77:4B": "Apple",
    "18:78:4B": "Apple",
    "18:79:4B": "Apple",
    "18:7A:4B": "Apple",
    "18:7B:4B": "Apple",
    "18:7C:4B": "Apple",
    "18:7D:4B": "Apple",
    "18:7E:4B": "Apple",
    "18:7F:4B": "Apple",
    "18:80:4B": "Apple",
    "18:81:4B": "Apple",
    "18:82:4B": "Apple",
    "18:83:4B": "Apple",
    "18:84:4B": "Apple",
    "18:85:4B": "Apple",
    "18:86:4B": "Apple",
    "18:87:4B": "Apple",
    "18:88:4B": "Apple",
    "18:89:4B": "Apple",
    "18:8A:4B": "Apple",
    "18:8B:4B": "Apple",
    "18:8C:4B": "Apple",
    "18:8D:4B": "Apple",
    "18:8E:4B": "Apple",
    "18:8F:4B": "Apple",
    "18:90:4B": "Apple",
    "18:91:4B": "Apple",
    "18:92:4B": "Apple",
    "18:93:4B": "Apple",
    "18:94:4B": "Apple",
    "18:95:4B": "Apple",
    "18:96:4B": "Apple",
    "18:97:4B": "Apple",
    "18:98:4B": "Apple",
    "18:99:4B": "Apple",
    "18:9A:4B": "Apple",
    "18:9B:4B": "Apple",
    "18:9C:4B": "Apple",
    "18:9D:4B": "Apple",
    "18:9E:4B": "Apple",
    "18:9F:4B": "Apple",
    "18:A0:4B": "Apple",
    "18:A1:4B": "Apple",
    "18:A2:4B": "Apple",
    "18:A3:4B": "Apple",
    "18:A4:4B": "Apple",
    "18:A5:4B": "Apple",
    "18:A6:4B": "Apple",
    "18:A7:4B": "Apple",
    "18:A8:4B": "Apple",
    "18:A9:4B": "Apple",
    "18:AA:4B": "Apple",
    "18:AB:4B": "Apple",
    "18:AC:4B": "Apple",
    "18:AD:4B": "Apple",
    "18:AE:4B": "Apple",
    "18:AF:4B": "Apple",
    "18:B0:4B": "Apple",
    "18:B1:4B": "Apple",
    "18:B2:4B": "Apple",
    "18:B3:4B": "Apple",
    "18:B4:4B": "Apple",
    "18:B5:4B": "Apple",
    "18:B6:4B": "Apple",
    "18:B7:4B": "Apple",
    "18:B8:4B": "Apple",
    "18:B9:4B": "Apple",
    "18:BA:4B": "Apple",
    "18:BB:4B": "Apple",
    "18:BC:4B": "Apple",
    "18:BD:4B": "Apple",
    "18:BE:4B": "Apple",
    "18:BF:4B": "Apple",
    "18:C0:4B": "Apple",
    "18:C1:4B": "Apple",
    "18:C2:4B": "Apple",
    "18:C3:4B": "Apple",
    "18:C4:4B": "Apple",
    "18:C5:4B": "Apple",
    "18:C6:4B": "Apple",
    "18:C7:4B": "Apple",
    "18:C8:4B": "Apple",
    "18:C9:4B": "Apple",
    "18:CA:4B": "Apple",
    "18:CB:4B": "Apple",
    "18:CC:4B": "Apple",
    "18:CD:4B": "Apple",
    "18:CE:4B": "Apple",
    "18:CF:4B": "Apple",
    "18:D0:4B": "Apple",
    "18:D1:4B": "Apple",
    "18:D2:4B": "Apple",
    "18:D3:4B": "Apple",
    "18:D4:4B": "Apple",
    "18:D5:4B": "Apple",
    "18:D6:4B": "Apple",
    "18:D7:4B": "Apple",
    "18:D8:4B": "Apple",
    "18:D9:4B": "Apple",
    "18:DA:4B": "Apple",
    "18:DB:4B": "Apple",
    "18:DC:4B": "Apple",
    "18:DD:4B": "Apple",
    "18:DE:4B": "Apple",
    "18:DF:4B": "Apple",
    "18:E0:4B": "Apple",
    "18:E1:4B": "Apple",
    "18:E2:4B": "Apple",
    "18:E3:4B": "Apple",
    "18:E4:4B": "Apple",
    "18:E5:4B": "Apple",
    "18:E6:4B": "Apple",
    "18:E7:4B": "Apple",
    "18:E8:4B": "Apple",
    "18:E9:4B": "Apple",
    "18:EA:4B": "Apple",
    "18:EB:4B": "Apple",
    "18:EC:4B": "Apple",
    "18:ED:4B": "Apple",
    "18:EE:4B": "Apple",
    "18:EF:4B": "Apple",
    "18:F0:4B": "Apple",
    "18:F1:4B": "Apple",
    "18:F2:4B": "Apple",
    "18:F3:4B": "Apple",
    "18:F4:4B": "Apple",
    "18:F5:4B": "Apple",
    "18:F6:4B": "Apple",
    "18:F7:4B": "Apple",
    "18:F8:4B": "Apple",
    "18:F9:4B": "Apple",
    "18:FA:4B": "Apple",
    "18:FB:4B": "Apple",
    "18:FC:4B": "Apple",
    "18:FD:4B": "Apple",
    "18:FE:4B": "Apple",
    "18:FF:4B": "Apple",
    "1C:0B:4B": "Apple",
    "1C:0C:4B": "Apple",
    "1C:0D:4B": "Apple",
    "1C:0E:4B": "Apple",
    "1C:0F:4B": "Apple",
    "1C:10:4B": "Apple",
    "1C:11:4B": "Apple",
    "1C:12:4B": "Apple",
    "1C:13:4B": "Apple",
    "1C:14:4B": "Apple",
    "1C:15:4B": "Apple",
    "1C:16:4B": "Apple",
    "1C:17:4B": "Apple",
    "1C:18:4B": "Apple",
    "1C:19:4B": "Apple",
    "1C:1A:4B": "Apple",
    "1C:1B:4B": "Apple",
    "1C:1C:4B": "Apple",
    "1C:1D:4B": "Apple",
    "1C:1E:4B": "Apple",
    "1C:1F:4B": "Apple",
    "1C:20:4B": "Apple",
    "1C:21:4B": "Apple",
    "1C:22:4B": "Apple",
    "1C:23:4B": "Apple",
    "1C:24:4B": "Apple",
    "1C:25:4B": "Apple",
    "1C:26:4B": "Apple",
    "1C:27:4B": "Apple",
    "1C:28:4B": "Apple",
    "1C:29:4B": "Apple",
    "1C:2A:4B": "Apple",
    "1C:2B:4B": "Apple",
    "1C:2C:4B": "Apple",
    "1C:2D:4B": "Apple",
    "1C:2E:4B": "Apple",
    "1C:2F:4B": "Apple",
    "1C:30:4B": "Apple",
    "1C:31:4B": "Apple",
    "1C:32:4B": "Apple",
    "1C:33:4B": "Apple",
    "1C:34:4B": "Apple",
    "1C:35:4B": "Apple",
    "1C:36:4B": "Apple",
    "1C:37:4B": "Apple",
    "1C:38:4B": "Apple",
    "1C:39:4B": "Apple",
    "1C:3A:4B": "Apple",
    "1C:3B:4B": "Apple",
    "1C:3C:4B": "Apple",
    "1C:3D:4B": "Apple",
    "1C:3E:4B": "Apple",
    "1C:3F:4B": "Apple",
    "1C:40:4B": "Apple",
    "1C:41:4B": "Apple",
    "1C:42:4B": "Apple",
    "1C:43:4B": "Apple",
    "1C:44:4B": "Apple",
    "1C:45:4B": "Apple",
    "1C:46:4B": "Apple",
    "1C:47:4B": "Apple",
    "1C:48:4B": "Apple",
    "1C:49:4B": "Apple",
    "1C:4A:4B": "Apple",
    "1C:4B:4B": "Apple",
    "1C:4C:4B": "Apple",
    "1C:4D:4B": "Apple",
    "1C:4E:4B": "Apple",
    "1C:4F:4B": "Apple",
    "1C:50:4B": "Apple",
    "1C:51:4B": "Apple",
    "1C:52:4B": "Apple",
    "1C:53:4B": "Apple",
    "1C:54:4B": "Apple",
    "1C:55:4B": "Apple",
    "1C:56:4B": "Apple",
    "1C:57:4B": "Apple",
    "1C:58:4B": "Apple",
    "1C:59:4B": "Apple",
    "1C:5A:4B": "Apple",
    "1C:5B:4B": "Apple",
    "1C:5C:4B": "Apple",
    "1C:5D:4B": "Apple",
    "1C:5E:4B": "Apple",
    "1C:5F:4B": "Apple",
    "1C:60:4B": "Apple",
    "1C:61:4B": "Apple",
    "1C:62:4B": "Apple",
    "1C:63:4B": "Apple",
    "1C:64:4B": "Apple",
    "1C:65:4B": "Apple",
    "1C:66:4B": "Apple",
    "1C:67:4B": "Apple",
    "1C:68:4B": "Apple",
    "1C:69:4B": "Apple",
    "1C:6A:4B": "Apple",
    "1C:6B:4B": "Apple",
    "1C:6C:4B": "Apple",
    "1C:6D:4B": "Apple",
    "1C:6E:4B": "Apple",
    "1C:6F:4B": "Apple",
    "1C:70:4B": "Apple",
    "1C:71:4B": "Apple",
    "1C:72:4B": "Apple",
    "1C:73:4B": "Apple",
    "1C:74:4B": "Apple",
    "1C:75:4B": "Apple",
    "1C:76:4B": "Apple",
    "1C:77:4B": "Apple",
    "1C:78:4B": "Apple",
    "1C:79:4B": "Apple",
    "1C:7A:4B": "Apple",
    "1C:7B:4B": "Apple",
    "1C:7C:4B": "Apple",
    "1C:7D:4B": "Apple",
    "1C:7E:4B": "Apple",
    "1C:7F:4B": "Apple",
    "1C:80:4B": "Apple",
    "1C:81:4B": "Apple",
    "1C:82:4B": "Apple",
    "1C:83:4B": "Apple",
    "1C:84:4B": "Apple",
    "1C:85:4B": "Apple",
    "1C:86:4B": "Apple",
    "1C:87:4B": "Apple",
    "1C:88:4B": "Apple",
    "1C:89:4B": "Apple",
    "1C:8A:4B": "Apple",
    "1C:8B:4B": "Apple",
    "1C:8C:4B": "Apple",
    "1C:8D:4B": "Apple",
    "1C:8E:4B": "Apple",
    "1C:8F:4B": "Apple",
    "1C:90:4B": "Apple",
    "1C:91:4B": "Apple",
    "1C:92:4B": "Apple",
    "1C:93:4B": "Apple",
    "1C:94:4B": "Apple",
    "1C:95:4B": "Apple",
    "1C:96:4B": "Apple",
    "1C:97:4B": "Apple",
    "1C:98:4B": "Apple",
    "1C:99:4B": "Apple",
    "1C:9A:4B": "Apple",
    "1C:9B:4B": "Apple",
    "1C:9C:4B": "Apple",
    "1C:9D:4B": "Apple",
    "1C:9E:4B": "Apple",
    "1C:9F:4B": "Apple",
    "1C:A0:4B": "Apple",
    "1C:A1:4B": "Apple",
    "1C:A2:4B": "Apple",
    "1C:A3:4B": "Apple",
    "1C:A4:4B": "Apple",
    "1C:A5:4B": "Apple",
    "1C:A6:4B": "Apple",
    "1C:A7:4B": "Apple",
    "1C:A8:4B": "Apple",
    "1C:A9:4B": "Apple",
    "1C:AA:4B": "Apple",
    "1C:AB:4B": "Apple",
    "1C:AC:4B": "Apple",
    "1C:AD:4B": "Apple",
    "1C:AE:4B": "Apple",
    "1C:AF:4B": "Apple",
    "1C:B0:4B": "Apple",
    "1C:B1:4B": "Apple",
    "1C:B2:4B": "Apple",
    "1C:B3:4B": "Apple",
    "1C:B4:4B": "Apple",
    "1C:B5:4B": "Apple",
    "1C:B6:4B": "Apple",
    "1C:B7:4B": "Apple",
    "1C:B8:4B": "Apple",
    "1C:B9:4B": "Apple",
    "1C:BA:4B": "Apple",
    "1C:BB:4B": "Apple",
    "1C:BC:4B": "Apple",
    "1C:BD:4B": "Apple",
    "1C:BE:4B": "Apple",
    "1C:BF:4B": "Apple",
    "1C:C0:4B": "Apple",
    "1C:C1:4B": "Apple",
    "1C:C2:4B": "Apple",
    "1C:C3:4B": "Apple",
    "1C:C4:4B": "Apple",
    "1C:C5:4B": "Apple",
    "1C:C6:4B": "Apple",
    "1C:C7:4B": "Apple",
    "1C:C8:4B": "Apple",
    "1C:C9:4B": "Apple",
    "1C:CA:4B": "Apple",
    "1C:CB:4B": "Apple",
    "1C:CC:4B": "Apple",
    "1C:CD:4B": "Apple",
    "1C:CE:4B": "Apple",
    "1C:CF:4B": "Apple",
}

def lookup_vendor(mac: str) -> str:
    """Look up MAC vendor from OUI prefix."""
    oui = mac.upper()[:8]
    return OUI_VENDORS.get(oui, "Unknown")


# ─── Logger ─────────────────────────────────────────────────────────────────

def setup_logging(log_file: str, level: str = "INFO"):
    logger = logging.getLogger("netmon")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh = logging.FileHandler(log_file) if log_file else logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


log = logging.getLogger("netmon")


# ─── Database ───────────────────────────────────────────────────────────────

class Database:
    """SQLite persistence for device state and bandwidth history."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        hostname TEXT DEFAULT '',
        vendor TEXT DEFAULT 'Unknown',
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        state TEXT DEFAULT 'unknown',
        state_changed REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bandwidth_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        rx_bytes REAL DEFAULT 0,
        tx_bytes REAL DEFAULT 0,
        rx_rate REAL DEFAULT 0,
        tx_rate REAL DEFAULT 0,
        FOREIGN KEY (mac) REFERENCES devices(mac)
    );

    CREATE TABLE IF NOT EXISTS interface_bandwidth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        interface TEXT NOT NULL,
        rx_bytes REAL DEFAULT 0,
        tx_bytes REAL DEFAULT 0,
        rx_rate REAL DEFAULT 0,
        tx_rate REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS state_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        mac TEXT NOT NULL,
        old_state TEXT NOT NULL,
        new_state TEXT NOT NULL,
        FOREIGN KEY (mac) REFERENCES devices(mac)
    );

    CREATE INDEX IF NOT EXISTS idx_bw_mac ON bandwidth_samples(mac, timestamp);
    CREATE INDEX IF NOT EXISTS idx_bw_iface ON interface_bandwidth(interface, timestamp);
    CREATE INDEX IF NOT EXISTS idx_state_mac ON state_history(mac, timestamp);
    """

    def __init__(self, db_path: str, retention_days: int = 90):
        self.db_path = db_path
        self.retention_days = retention_days
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            for stmt in self.SCHEMA.split(";"):
                stmt = stmt.strip()
                if stmt:
                    self.conn.execute(stmt)
            self.conn.commit()

    @contextmanager
    def cursor(self):
        with self.lock:
            cur = self.conn.cursor()
            try:
                yield cur
            finally:
                self.conn.commit()
                cur.close()

    def upsert_device(self, mac: str, ip: str, hostname: str = "",
                      vendor: str = "Unknown", state: str = "online"):
        now = time.time()
        with self.cursor() as cur:
            cur.execute("SELECT state, state_changed FROM devices WHERE mac = ?", (mac,))
            row = cur.fetchone()
            old_state = row["state"] if row else None
            state_changed = row["state_changed"] if row else now

            if old_state != state:
                state_changed = now
                if old_state:
                    cur.execute(
                        "INSERT INTO state_history (timestamp, mac, old_state, new_state) VALUES (?, ?, ?, ?)",
                        (now, mac, old_state, state)
                    )

            cur.execute("""
                INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, state, state_changed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE vendor END,
                    last_seen = excluded.last_seen,
                    state = excluded.state,
                    state_changed = excluded.state_changed
            """, (mac, ip, hostname, vendor, now if not row else row["first_seen"],
                  now, state, state_changed))

    def record_bandwidth(self, mac: str, ip: str, rx_bytes: float, tx_bytes: float,
                         rx_rate: float, tx_rate: float):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO bandwidth_samples (timestamp, mac, ip, rx_bytes, tx_bytes, rx_rate, tx_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (time.time(), mac, ip, rx_bytes, tx_bytes, rx_rate, tx_rate))

    def record_interface_bw(self, interface: str, rx_bytes: float, tx_bytes: float,
                            rx_rate: float, tx_rate: float):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO interface_bandwidth (timestamp, interface, rx_bytes, tx_bytes, rx_rate, tx_rate)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (time.time(), interface, rx_bytes, tx_bytes, rx_rate, tx_rate))

    def get_devices(self) -> List[Dict]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(row) for row in cur.fetchall()]

    def get_device_bandwidth(self, mac: str, since: float) -> List[Dict]:
        with self.cursor() as cur:
            cur.execute("""
                SELECT * FROM bandwidth_samples
                WHERE mac = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            """, (mac, since))
            return [dict(row) for row in cur.fetchall()]

    def get_interface_bandwidth(self, interface: str, since: float) -> List[Dict]:
        with self.cursor() as cur:
            cur.execute("""
                SELECT * FROM interface_bandwidth
                WHERE interface = ? AND timestamp >= ?
                ORDER BY timestamp ASC
            """, (interface, since))
            return [dict(row) for row in cur.fetchall()]

    def purge_old(self):
        cutoff = time.time() - (self.retention_days * 86400)
        with self.cursor() as cur:
            cur.execute("DELETE FROM bandwidth_samples WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM interface_bandwidth WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM state_history WHERE timestamp < ?", (cutoff,))
            cur.execute("""
                DELETE FROM devices WHERE last_seen < ?
                AND state = 'offline'
            """, (cutoff,))

    def close(self):
        self.conn.close()


# ─── Network Utilities ──────────────────────────────────────────────────────

def get_default_interface() -> str:
    """Get the first non-loopback interface with a default route."""
    gateways = netifaces.gateways()
    if "default" in gateways and netifaces.AF_INET in gateways["default"]:
        return gateways["default"][netifaces.AF_INET][1]
    for iface in netifaces.interfaces():
        if iface != "lo":
            return iface
    return "eth0"


def get_interface_ip_and_netmask(iface: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            info = addrs[netifaces.AF_INET][0]
            return info.get("addr"), info.get("netmask")
    except Exception:
        pass
    return None, None


def get_interface_cidr(iface: str) -> Optional[str]:
    ip, mask = get_interface_ip_and_netmask(iface)
    if ip and mask:
        try:
            # Convert dotted-decimal netmask to prefix length
            mask_bits = sum(bin(int(x)).count("1") for x in mask.split("."))
            network = ip_address(ip).network_address
            from ipaddress import IPv4Network
            return str(IPv4Network(f"{network}/{mask_bits}", strict=False))
        except Exception:
            return None
    return None


def get_own_mac(iface: str) -> str:
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_LINK in addrs:
            return addrs[netifaces.AF_LINK][0].get("addr", "").lower()
    except Exception:
        pass
    return ""


def resolve_hostname(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror):
        return ""


# ─── Device Discovery (ARP) ────────────────────────────────────────────────

class ARPDiscoverer:
    """Silent ARP sweep to discover live devices on the subnet."""

    def __init__(self, interface: str, timeout: float = 3.0):
        self.interface = interface
        self.timeout = timeout
        self.own_mac = get_own_mac(interface)
        self.own_ip = get_interface_ip_and_netmask(interface)[0]

    def sweep(self, subnet: str) -> List[Dict]:
        """Perform an ARP scan on the given subnet. Returns list of {ip, mac}."""
        try:
            conf.iface = self.interface
            conf.verb = 0  # completely silent

            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=self.timeout,
                iface=self.interface,
                inter=0.01,       # 10ms between packets
                verbose=False,
                retry=1
            )

            devices = []
            seen = set()
            for sent, recv in ans:
                mac = recv[Ether].src.lower()
                ip = recv[ARP].psrc

                # Skip self
                if mac == self.own_mac or ip == self.own_ip:
                    continue
                if mac in seen:
                    continue

                seen.add(mac)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": lookup_vendor(mac)
                })

            return devices

        except Exception as e:
            log.warning(f"ARP sweep failed: {e}")
            return []


# ─── Online/Offline Monitor (Adaptive ICMP) ────────────────────────────────

class StateMonitor:
    """Adaptive ping-based online/offline detection with exponential backoff."""

    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config
        self.devices: Dict[str, Dict] = {}  # mac -> device info
        self.last_checks: Dict[str, float] = {}
        self.backoff: Dict[str, int] = {}    # mac -> current interval
        self.lock = threading.Lock()

    def update_devices(self, devices: List[Dict]):
        with self.lock:
            for d in devices:
                mac = d["mac"]
                if mac not in self.devices:
                    self.backoff[mac] = self.config.online_check_interval
                self.devices[mac] = d
                # Ensure device record exists
                self.db.upsert_device(
                    mac=d["mac"], ip=d["ip"],
                    vendor=d.get("vendor", "Unknown"),
                    state=self.devices[mac].get("state", "unknown")
                )

    def _ping(self, ip: str) -> bool:
        """Single silent ICMP check. Returns True if reachable."""
        try:
            # Use system ping for low overhead
            result = subprocess.run(
                ["ping", "-c", str(self.config.ping_count),
                 "-W", str(int(self.config.ping_timeout)),
                 "-q", "-n", ip],
                capture_output=True,
                text=True,
                timeout=self.config.ping_timeout + 0.5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def check_device(self, mac: str) -> bool:
        """Check a single device's online status."""
        device = self.devices.get(mac)
        if not device:
            return False
        return self._ping(device["ip"])

    def check_all(self):
        """Check all known devices with adaptive intervals."""
        with self.lock:
            now = time.time()
            to_check = []

            for mac, device in list(self.devices.items()):
                interval = self.backoff.get(mac, self.config.online_check_interval)
                last = self.last_checks.get(mac, 0)
                if now - last >= interval:
                    to_check.append(mac)

        for mac in to_check:
            try:
                device = self.devices.get(mac)
                if not device:
                    continue

                is_online = self._ping(device["ip"])
                old_state = device.get("state", "unknown")
                new_state = "online" if is_online else "offline"

                with self.lock:
                    device["state"] = new_state
                    self.last_checks[mac] = time.time()

                self.db.upsert_device(
                    mac=device["mac"], ip=device["ip"],
                    hostname=device.get("hostname", ""),
                    vendor=device.get("vendor", "Unknown"),
                    state=new_state
                )

                if new_state == "online":
                    self.backoff[mac] = self.config.online_check_interval
                else:
                    # Exponential backoff for offline devices
                    current = self.backoff.get(mac, self.config.offline_check_interval)
                    self.backoff[mac] = min(
                        current * 2,
                        self.config.max_offline_backoff
                    )

                if old_state != new_state:
                    log.info(f"Device {device['ip']} ({device.get('vendor', '?')}) "
                             f"state changed: {old_state} -> {new_state}")

            except Exception as e:
                log.warning(f"Error checking {mac}: {e}")

    def get_device_count(self) -> Tuple[int, int]:
        with self.lock:
            online = sum(1 for d in self.devices.values() if d.get("state") == "online")
            offline = sum(1 for d in self.devices.values() if d.get("state") == "offline")
            return online, offline


# ─── Bandwidth Monitor ─────────────────────────────────────────────────────

class BandwidthMonitor:
    """Tracks bandwidth at interface level (psutil) and per-device (iptables)."""

    def __init__(self, db: Database, config: Config, iface: str):
        self.db = db
        self.config = config
        self.iface = iface
        self.prev_iface_counters: Dict[str, Tuple[int, int]] = {}
        self.prev_time = time.time()

        # iptables per-IP tracking
        self.iptables_initialized = False
        if config.use_iptables:
            self._init_iptables()

    def _init_iptables(self):
        """Create iptables chain for per-IP accounting."""
        try:
            chain = self.config.iptables_chain
            # Create chain
            subprocess.run(
                ["iptables", "-N", chain],
                capture_output=True, text=True, check=False
            )
            # Add to INPUT and FORWARD if not already there
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
        except FileNotFoundError:
            log.warning("iptables not available; falling back to interface-level only")
        except Exception as e:
            log.warning(f"iptables init failed: {e}")

    def _get_iptables_counts(self) -> Dict[str, Dict[str, int]]:
        """Read per-IP byte counts from iptables accounting chain."""
        result = {}
        if not self.iptables_initialized:
            return result
        try:
            chain = self.config.iptables_chain
            output = subprocess.run(
                ["iptables", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True, check=True
            ).stdout

            for line in output.splitlines():
                # Parse: pkts bytes target prot opt in out source destination
                parts = line.strip().split()
                if len(parts) >= 8 and parts[2] == "ACCEPT":
                    try:
                        bytes_val = int(parts[1])
                        src = parts[7]
                        dst = parts[8]
                        if src not in result:
                            result[src] = {"rx": 0, "tx": 0}
                        if dst not in result:
                            result[dst] = {"rx": 0, "tx": 0}
                        result[src]["tx"] += bytes_val
                        result[dst]["rx"] += bytes_val
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            log.warning(f"iptables read failed: {e}")
        return result

    def sample_interface(self):
        """Sample interface-level bandwidth and store to DB."""
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
        """Map iptables byte counts to known devices and store."""
        if not self.iptables_initialized:
            return

        ip_counts = self._get_iptables_counts()
        now = time.time()

        for mac, device in devices.items():
            ip = device.get("ip")
            if ip and ip in ip_counts:
                counts = ip_counts[ip]
                self.db.record_bandwidth(
                    mac=mac, ip=ip,
                    rx_bytes=counts["rx"],
                    tx_bytes=counts["tx"],
                    rx_rate=0,  # Requires differential; stored raw
                    tx_rate=0
                )

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


# ─── Export / Reporting ────────────────────────────────────────────────────

class Exporter:
    """JSON and CSV export of current network state."""

    def __init__(self, db: Database, export_dir: str):
        self.db = db
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self, filename: str = "netmon_snapshot.json"):
        devices = self.db.get_devices()
        snapshot = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "device_count": len(devices),
            "online_count": sum(1 for d in devices if d.get("state") == "online"),
            "offline_count": sum(1 for d in devices if d.get("state") == "offline"),
            "devices": devices
        }
        path = self.export_dir / filename
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2, default=str)
        return path

    def export_csv(self, filename: str = "netmon_devices.csv"):
        devices = self.db.get_devices()
        path = self.export_dir / filename
        if not devices:
            return path
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        return path


# ─── Main Daemon ───────────────────────────────────────────────────────────

class NetMonDaemon:
    """Coordinator for all monitoring threads."""

    def __init__(self, config: Config):
        self.config = config
        self.running = threading.Event()
        self.running.set()

        # Resolve interface
        if config.interface == "auto":
            self.iface = get_default_interface()
        else:
            self.iface = config.interface

        # Resolve subnet
        if config.target_subnet == "auto":
            cidr = get_interface_cidr(self.iface)
            if not cidr:
                log.error("Could not determine subnet; specify --subnet")
                sys.exit(1)
            self.subnet = cidr
        else:
            self.subnet = config.target_subnet

        log.info(f"Monitoring interface: {self.iface}")
        log.info(f"Monitoring subnet: {self.subnet}")

        # Initialize components
        self.db = Database(config.db_path, config.db_retention_days)
        self.discoverer = ARPDiscoverer(self.iface, config.discovery_timeout)
        self.state_monitor = StateMonitor(self.db, config)
        self.bandwidth_monitor = BandwidthMonitor(self.db, config, self.iface)
        self.exporter = Exporter(self.db, config.export_dir)

        # Track discovered devices with hostnames
        self.devices: Dict[str, Dict] = {}
        self.last_discovery = 0
        self.last_json_export = 0
        self.last_csv_export = 0
        self.last_purge = 0

    def _resolve_hostnames(self, devices: List[Dict]):
        """Resolve hostnames for new devices (non-blocking, threaded)."""
        for d in devices:
            mac = d["mac"]
            if mac in self.devices and self.devices[mac].get("hostname"):
                d["hostname"] = self.devices[mac]["hostname"]
            else:
                name = resolve_hostname(d["ip"])
                d["hostname"] = name
                if name:
                    log.debug(f"Resolved {d['ip']} -> {name}")

    def _discovery_cycle(self):
        """Full ARP discovery sweep."""
        log.info("Running discovery sweep...")
        devices = self.discoverer.sweep(self.subnet)
        self._resolve_hostnames(devices)

        # Merge: update existing entries, add new ones, keep offline entries
        discovered_macs = {d["mac"] for d in devices}
        for d in devices:
            mac = d["mac"]
            d["state"] = self.devices.get(mac, {}).get("state", "online")
            self.devices[mac] = d

        # Mark unreachable devices that we already know about
        for mac in list(self.devices.keys()):
            if mac not in discovered_macs:
                # Don't immediately mark offline, let ping decide
                pass

        # Feed to state monitor
        self.state_monitor.update_devices(list(self.devices.values()))
        self.last_discovery = time.time()
        log.info(f"Discovery complete: {len(devices)} live devices, "
                 f"{len(self.devices)} known total")

    def _bandwidth_cycle(self):
        """Sample interface and per-device bandwidth."""
        self.bandwidth_monitor.sample_interface()
        self.bandwidth_monitor.sample_per_device(self.devices)

    def _export_cycle(self):
        """Periodic JSON/CSV export."""
        now = time.time()
        if now - self.last_json_export >= self.config.json_export_interval:
            path = self.exporter.export_json()
            log.debug(f"JSON export: {path}")
            self.last_json_export = now

        if now - self.last_csv_export >= self.config.csv_export_interval:
            path = self.exporter.export_csv()
            log.debug(f"CSV export: {path}")
            self.last_csv_export = now

    def _purge_cycle(self):
        """Periodic old data cleanup."""
        now = time.time()
        if now - self.last_purge >= 3600:  # hourly
            self.db.purge_old()
            self.last_purge = now

    def run(self):
        """Main loop. Runs discovery, state checks, and bandwidth sampling."""
        log.info("NetMon daemon started")
        log.info(f"Devices will be checked every {self.config.online_check_interval}s "
                 f"(online) / adaptive backoff (offline)")
        log.info(f"Bandwidth sampled every {self.config.bandwidth_interval}s")
        log.info(f"Full ARP discovery every {self.config.discovery_interval}s")

        # Initial discovery
        self._discovery_cycle()

        last_discovery_check = time.time()
        last_bw_sample = time.time()
        last_state_check = time.time()
        last_status = time.time()

        try:
            while self.running.is_set():
                now = time.time()

                # Discovery cycle
                if now - self.last_discovery >= self.config.discovery_interval:
                    self._discovery_cycle()
                    last_discovery_check = now

                # State check cycle
                if now - last_state_check >= 1:  # Check at most once per second
                    self.state_monitor.check_all()
                    last_state_check = now

                # Bandwidth cycle
                if now - last_bw_sample >= self.config.bandwidth_interval:
                    self._bandwidth_cycle()
                    last_bw_sample = now

                # Export cycle
                self._export_cycle()

                # Purge cycle
                self._purge_cycle()

                # Periodic status log (every 5 min)
                if now - last_status >= 300:
                    online, offline = self.state_monitor.get_device_count()
                    iface_bw = self.db.get_interface_bandwidth(
                        self.iface, now - 60
                    )
                    total_rx = sum(s.get("rx_rate", 0) for s in iface_bw[-12:]) / max(len(iface_bw[-12:]), 1)
                    total_tx = sum(s.get("tx_rate", 0) for s in iface_bw[-12:]) / max(len(iface_bw[-12:]), 1)
                    log.info(
                        f"Status: {online} online, {offline} offline | "
                        f"Interface {self.iface}: "
                        f"{self._format_bw(total_rx)} RX / {self._format_bw(total_tx)} TX"
                    )
                    last_status = now

                time.sleep(0.5)  # Poll interval - prevents busy-waiting

        except KeyboardInterrupt:
            log.info("Shutdown requested")
        finally:
            self.shutdown()

    def _format_bw(self, bps: float) -> str:
        """Format bits per second to human-readable."""
        if bps < 1024:
            return f"{bps:.1f} B/s"
        elif bps < 1024 * 1024:
            return f"{bps / 1024:.1f} KB/s"
        elif bps < 1024 * 1024 * 1024:
            return f"{bps / (1024 * 1024):.1f} MB/s"
        else:
            return f"{bps / (1024 * 1024 * 1024):.2f} GB/s"

    def shutdown(self):
        """Graceful shutdown."""
        log.info("Shutting down...")
        self.bandwidth_monitor.cleanup_iptables()
        self.db.close()
        self.running.clear()
        log.info("NetMon stopped")



    def get_snapshot(self) -> Dict:
        """Get current state as dictionary (for live queries)."""
        devices = self.db.get_devices()
        now = time.time()
        since = now - 60  # last 60 seconds
        iface_bw = self.db.get_interface_bandwidth(self.iface, since)

        avg_rx = sum(s.get("rx_rate", 0) for s in iface_bw) / max(len(iface_bw), 1)
        avg_tx = sum(s.get("tx_rate", 0) for s in iface_bw) / max(len(iface_bw), 1)

        return {
            "timestamp": now,
            "interface": self.iface,
            "subnet": self.subnet,
            "device_count": len(devices),
            "online_count": sum(1 for d in devices if d.get("state") == "online"),
            "offline_count": sum(1 for d in devices if d.get("state") == "offline"),
            "unknown_count": sum(1 for d in devices if d.get("state") == "unknown"),
            "interface_rx_rate": avg_rx,
            "interface_tx_rate": avg_tx,
            "devices": [
                {
                    "ip": d["ip"],
                    "mac": d["mac"],
                    "vendor": d.get("vendor", "Unknown"),
                    "hostname": d.get("hostname", ""),
                    "state": d.get("state", "unknown"),
                    "first_seen": d.get("first_seen", 0),
                    "last_seen": d.get("last_seen", 0),
                    "state_changed": d.get("state_changed", 0),
                }
                for d in devices
            ],
        }



    def parse_args():
    parser = argparse.ArgumentParser(
        description="NetMon - Silent Network Monitoring Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  netmon --daemonize                       # Run as daemon\n"
            "  netmon --interface eth0 --subnet 10.0.0.0/24  # Custom network\n"
            "  netmon --snapshot                        # One-shot JSON dump\n"
            "  netmon --live                            # Interactive console\n"
        ),
    )

    parser.add_argument("-i", "--interface", default="auto",
                        help="Network interface (default: auto-detect)")
    parser.add_argument("-s", "--subnet", default="auto",
                        help="Target subnet CIDR (default: auto)")
    parser.add_argument("-d", "--daemonize", action="store_true",
                        help="Run as background daemon")
    parser.add_argument("--db", default="/var/lib/netmon/netmon.db",
                        help="Database path")
    parser.add_argument("--log", default="/var/log/netmon.log",
                        help="Log file path")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level")
    parser.add_argument("--snapshot", action="store_true",
                        help="Print one-shot JSON snapshot and exit")
    parser.add_argument("--live", action="store_true",
                        help="Interactive live TUI display")
    parser.add_argument("--discovery-interval", type=int, default=60,
                        help="ARP discovery interval (seconds)")
    parser.add_argument("--online-interval", type=int, default=10,
                        help="Online check interval (seconds)")
    parser.add_argument("--offline-interval", type=int, default=120,
                        help="Offline check interval base (seconds)")
    parser.add_argument("--bw-interval", type=int, default=5,
                        help="Bandwidth sample interval (seconds)")
    parser.add_argument("--no-iptables", action="store_true",
                        help="Disable per-device iptables accounting")
    parser.add_argument("--export-dir", default="/var/lib/netmon/exports",
                        help="Export directory for JSON/CSV")
    parser.add_argument("--retention", type=int, default=90,
                        help="Days to retain bandwidth history")
    parser.add_argument("--pidfile", default="/var/run/netmon.pid",
                        help="PID file path")

    return parser.parse_args()


def daemonize(pidfile: str):
    """Fork and detach into background daemon process."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Parent exits
    except OSError as e:
        sys.stderr.write(f"Fork failed: {e}\n")
        sys.exit(1)

    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Second fork failed: {e}\n")
        sys.exit(1)

    # Redirect stdio to /dev/null
    sys.stdout.flush()
    sys.stderr.flush()
    with open("/dev/null", "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open("/dev/null", "a") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())

    # Write PID file
    with open(pidfile, "w") as f:
        f.write(str(os.getpid()))

    # Handle PID cleanup on exit
    def cleanup(signum=None, frame=None):
        if os.path.exists(pidfile):
            os.unlink(pidfile)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)


def run_live_display(daemon: NetMonDaemon):
    """Simple live TUI using ANSI escape sequences."""
    try:
        while daemon.running.is_set():
            snap = daemon.get_snapshot()
            os.system("clear")  # or use print(\033c) for pure ANSI
            print("=" * 72)
            print(f"  NetMon Live Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Interface: {snap['interface']}  Subnet: {snap['subnet']}")
            print("=" * 72)
            print(f"  Devices: {snap['device_count']} total | "
                  f"{snap['online_count']} online | "
                  f"{snap['offline_count']} offline | "
                  f"{snap['unknown_count']} unknown")
            print(f"  Bandwidth: {daemon._format_bw(snap['interface_rx_rate'])} RX / "
                  f"{daemon._format_bw(snap['interface_tx_rate'])} TX")
            print("-" * 72)
            print(f"  {'IP':<16} {'MAC':<18} {'Vendor':<16} {'State':<8} {'BW RX':<12} {'BW TX':<12}")
            print("-" * 72)

            for dev in snap["devices"][:20]:  # Show first 20
                mac = dev["mac"]
                recent_bw = daemon.db.get_device_bandwidth(mac, time.time() - 60)
                rx_rate = sum(s.get("rx_rate", 0) for s in recent_bw) / max(len(recent_bw), 1)
                tx_rate = sum(s.get("tx_rate", 0) for s in recent_bw) / max(len(recent_bw), 1)
                print(f"  {dev['ip']:<16} {dev['mac']:<18} "
                      f"{dev['vendor'][:16]:<16} {dev['state']:<8} "
                      f"{daemon._format_bw(rx_rate):<12} {daemon._format_bw(tx_rate):<12}")

            print(f"\n  Press Ctrl+C to exit")
            time.sleep(2)

    except KeyboardInterrupt:
        pass


def main():
    args = parse_args()

    # Build config from args
    config = Config(
        interface=args.interface,
        target_subnet=args.subnet,
        discovery_interval=args.discovery_interval,
        online_check_interval=args.online_interval,
        offline_check_interval=args.offline_interval,
        bandwidth_interval=args.bw_interval,
        use_iptables=not args.no_iptables,
        db_path=args.db,
        log_file=args.log,
        log_level=args.log_level,
        export_dir=args.export_dir,
        db_retention_days=args.retention,
        pid_file=args.pidfile,
        daemonize=args.daemonize,
    )

    # Setup logging
    setup_logging(config.log_file, config.log_level)
    log = logging.getLogger("netmon")

    # Daemonize if requested
    if args.daemonize:
        daemonize(args.pidfile)

    # Create and run daemon
    daemon = NetMonDaemon(config)

    if args.snapshot:
        daemon._discovery_cycle()
        time.sleep(5)  # Let initial checks settle
        snap = daemon.get_snapshot()
        print(json.dumps(snap, indent=2, default=str))
        daemon.shutdown()
        return

    if args.live:
        # Start daemon in background thread, show live TUI
        dt = threading.Thread(target=daemon.run, daemon=True)
        dt.start()
        time.sleep(2)
        run_live_display(daemon)
        daemon.running.clear()
        daemon.shutdown()
        return

    # Run in foreground
    daemon.run()


if __name__ == "__main__":
    main()