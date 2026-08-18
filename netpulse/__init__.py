"""Netpulse — a self-hosted LAN monitoring daemon.

Discovers devices, tracks presence with adaptive ICMP heartbeats, accounts
bandwidth per device and per interface, and persists it all to SQLite — with
no external egress. Everything stays on the LAN it monitors.
"""

__version__ = "1.0.0"
