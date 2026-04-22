#!/usr/bin/env python3
"""PCAP File Analyzer Module"""
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from collections import Counter

class Analyzer:
    def __init__(self, filepath, proto_filter, logger):
        self.filepath = filepath
        self.proto_filter = proto_filter
        self.logger = logger

    def run(self):
        self.logger.info(f"[*] Analyzing: {self.filepath}")
        try:
            packets = rdpcap(self.filepath)
        except Exception as e:
            self.logger.error(f"Failed to read pcap: {e}"); return

        total = len(packets)
        self.logger.success(f"Loaded {total} packets")

        # Stats
        protos = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        ports = Counter()

        for pkt in packets:
            if pkt.haslayer(IP):
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
                if pkt.haslayer(TCP):
                    protos["TCP"] += 1
                    ports[pkt[TCP].dport] += 1
                elif pkt.haslayer(UDP):
                    protos["UDP"] += 1
                    ports[pkt[UDP].dport] += 1
                elif pkt.haslayer(ICMP):
                    protos["ICMP"] += 1
            elif pkt.haslayer(ARP):
                protos["ARP"] += 1

        # Filter
        if self.proto_filter != "all":
            packets = [p for p in packets if self.proto_filter.upper() in p.summary().upper()]

        self.logger.info(f"
--- Protocol Distribution ---")
        for proto, count in protos.most_common():
            self.logger.success(f"  {proto}: {count} ({count/total*100:.1f}%)")

        self.logger.info(f"
--- Top 5 Source IPs ---")
        for ip, count in src_ips.most_common(5):
            self.logger.success(f"  {ip}: {count} packets")

        self.logger.info(f"
--- Top 5 Destination Ports ---")
        for port, count in ports.most_common(5):
            self.logger.success(f"  Port {port}: {count} hits")

        # Look for suspicious patterns
        self.logger.info(f"
--- Anomaly Detection ---")
        for ip, count in src_ips.most_common(3):
            if count > total * 0.3:
                self.logger.warning(f"⚠ High traffic from {ip}: {count} packets ({count/total*100:.1f}%) — possible scan/flood")

        self.logger.info("[+] Analysis complete")
