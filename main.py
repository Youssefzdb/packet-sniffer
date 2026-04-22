#!/usr/bin/env python3
"""
PacketSniffer v1.0 — Network Packet Capture & Protocol Analysis Tool
Author: Shadow Core
"""
import argparse, sys
from modules.sniffer import Sniffer
from modules.analyzer import Analyzer
from modules.http_parser import HTTPParser
from modules.dns_monitor import DNSMonitor
from utils.banner import banner
from utils.logger import Logger

def main():
    banner()
    p = argparse.ArgumentParser(description="PacketSniffer — Network Analysis Tool")
    sub = p.add_subparsers(dest="module")

    s = sub.add_parser("sniff", help="Capture live packets")
    s.add_argument("--iface", default="eth0", help="Network interface")
    s.add_argument("--count", type=int, default=100, help="Packets to capture")
    s.add_argument("--filter", default="", help="BPF filter (e.g. tcp port 80)")
    s.add_argument("--output", default="capture.pcap", help="Output pcap file")

    a = sub.add_parser("analyze", help="Analyze captured pcap file")
    a.add_argument("--file", required=True, help="Input .pcap file")
    a.add_argument("--proto", choices=["all","tcp","udp","icmp","arp"], default="all")

    d = sub.add_parser("dns", help="Monitor DNS queries in real-time")
    d.add_argument("--iface", default="eth0")
    d.add_argument("--count", type=int, default=50)

    h = sub.add_parser("http", help="Capture & parse HTTP traffic")
    h.add_argument("--iface", default="eth0")
    h.add_argument("--count", type=int, default=50)

    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if not args.module:
        p.print_help(); sys.exit(0)

    log = Logger(args.verbose if hasattr(args, "verbose") else False)

    if args.module == "sniff":
        Sniffer(args.iface, args.count, args.filter, args.output, log).run()
    elif args.module == "analyze":
        Analyzer(args.file, args.proto, log).run()
    elif args.module == "dns":
        DNSMonitor(args.iface, args.count, log).run()
    elif args.module == "http":
        HTTPParser(args.iface, args.count, log).run()

if __name__ == "__main__":
    main()
