"""Netpulse CLI: argument parsing, live TUI display, and entrypoint."""

import argparse
import json
import logging
import os
import threading
import time
from datetime import datetime

from .config import Config
from .daemon import NetpulseDaemon, daemonize
from .logging_setup import setup_logging


def parse_args():
    parser = argparse.ArgumentParser(
        description="Netpulse - Silent Network Monitoring Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  netpulse --daemonize                       # Run as daemon\n"
            "  netpulse --interface eth0 --subnet 10.0.0.0/24  # Custom network\n"
            "  netpulse --snapshot                        # One-shot JSON dump\n"
            "  netpulse --live                            # Interactive console\n"
        ),
    )

    parser.add_argument("-i", "--interface", default="auto",
                        help="Network interface (default: auto-detect)")
    parser.add_argument("-s", "--subnet", default="auto",
                        help="Target subnet CIDR (default: auto)")
    parser.add_argument("-d", "--daemonize", action="store_true",
                        help="Run as background daemon")
    parser.add_argument("--db", default="/var/lib/netpulse/netpulse.db",
                        help="Database path")
    parser.add_argument("--log", default="/var/log/netpulse.log",
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
    parser.add_argument("--export-dir", default="/var/lib/netpulse/exports",
                        help="Export directory for JSON/CSV")
    parser.add_argument("--retention", type=int, default=90,
                        help="Days to retain bandwidth history")
    parser.add_argument("--pidfile", default="/var/run/netpulse.pid",
                        help="PID file path")

    return parser.parse_args()


def run_live_display(daemon: NetpulseDaemon):
    """Simple live TUI using ANSI escape sequences."""
    try:
        while daemon.running.is_set():
            snap = daemon.get_snapshot()
            os.system("clear")  # or use print(\033c) for pure ANSI
            print("=" * 72)
            print(f"  Netpulse Live Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
    log = logging.getLogger("netpulse")

    # Daemonize if requested
    if args.daemonize:
        daemonize(args.pidfile)

    # Create and run daemon
    daemon = NetpulseDaemon(config)

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
