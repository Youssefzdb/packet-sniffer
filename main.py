#!/usr/bin/env python3
"""
ShadowSniffer — Network Packet Analyzer v1.0
Author: Shadow Core
Requires: root/sudo privileges
"""
import argparse, sys
from modules.capture import PacketCapture
from modules.dns_monitor import DNSMonitor
from modules.http_sniffer import HTTPSniffer
from modules.arp_watch import ARPWatch
from modules.stats import TrafficStats
from modules.interfaces import list_interfaces
from utils.banner import print_banner
from utils.logger import Logger

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="ShadowSniffer — Network Packet Analyzer")
    sub = parser.add_subparsers(dest="module")

    # interfaces
    sub.add_parser("interfaces", help="List available network interfaces")

    # capture
    cap = sub.add_parser("capture", help="Capture & analyze packets")
    cap.add_argument("--iface", default="eth0", help="Network interface")
    cap.add_argument("--count", type=int, default=50, help="Packet count")
    cap.add_argument("--filter", default="", help="BPF filter (e.g. 'tcp port 80')")
    cap.add_argument("--save", help="Save to PCAP file")

    # dns
    dns = sub.add_parser("dns", help="Monitor DNS queries & responses")
    dns.add_argument("--iface", default="eth0")
    dns.add_argument("--count", type=int, default=100)

    # http
    http = sub.add_parser("http", help="Sniff HTTP traffic")
    http.add_argument("--iface", default="eth0")
    http.add_argument("--count", type=int, default=200)

    # arp
    arp = sub.add_parser("arp", help="ARP spoofing detection")
    arp.add_argument("--iface", default="eth0")
    arp.add_argument("--count", type=int, default=500)

    # stats
    stats = sub.add_parser("stats", help="Live traffic statistics")
    stats.add_argument("--iface", default="eth0")
    stats.add_argument("--interval", type=int, default=5, help="Stats interval (seconds)")
    stats.add_argument("--count", type=int, default=1000)

    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(0)

    log = Logger(getattr(args, "verbose", False))

    if args.module == "interfaces":
        list_interfaces(log)
    elif args.module == "capture":
        PacketCapture(args.iface, args.count, args.filter, args.save, log).run()
    elif args.module == "dns":
        DNSMonitor(args.iface, args.count, log).run()
    elif args.module == "http":
        HTTPSniffer(args.iface, args.count, log).run()
    elif args.module == "arp":
        ARPWatch(args.iface, args.count, log).run()
    elif args.module == "stats":
        TrafficStats(args.iface, args.count, args.interval, log).run()

if __name__ == "__main__":
    main()
