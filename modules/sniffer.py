#!/usr/bin/env python3
"""Live Packet Capture Module using Scapy"""
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP
import time

class Sniffer:
    def __init__(self, iface, count, bpf_filter, output, logger):
        self.iface = iface
        self.count = count
        self.filter = bpf_filter
        self.output = output
        self.logger = logger
        self.packets = []

    def _process(self, pkt):
        self.packets.append(pkt)
        summary = self._summarize(pkt)
        self.logger.info(summary)

    def _summarize(self, pkt) -> str:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "IP"
            sport = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else ""
            dport = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else ""
            return f"[{proto}] {src}:{sport} -> {dst}:{dport} | len={len(pkt)}"
        elif pkt.haslayer(ARP):
            return f"[ARP] {pkt[ARP].psrc} -> {pkt[ARP].pdst} | op={pkt[ARP].op}"
        return f"[PKT] {pkt.summary()}"

    def run(self):
        self.logger.info(f"[*] Sniffing on {self.iface} | count={self.count} | filter='{self.filter}'")
        self.logger.warning("[!] Requires root/sudo privileges")
        try:
            sniff(
                iface=self.iface,
                prn=self._process,
                count=self.count,
                filter=self.filter if self.filter else None,
                store=False
            )
            if self.output and self.packets:
                wrpcap(self.output, self.packets)
                self.logger.success(f"Saved {len(self.packets)} packets to {self.output}")
        except PermissionError:
            self.logger.error("Permission denied. Run with sudo.")
        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
