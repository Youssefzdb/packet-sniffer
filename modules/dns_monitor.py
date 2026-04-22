#!/usr/bin/env python3
"""DNS Traffic Monitor Module"""
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
from collections import Counter

class DNSMonitor:
    def __init__(self, iface, count, logger):
        self.iface = iface
        self.count = count
        self.logger = logger
        self.queries = Counter()
        self.responses = []

    def _process(self, pkt):
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            src = pkt[IP].src if pkt.haslayer(IP) else "?"

            if dns.qr == 0 and dns.haslayer(DNSQR):  # Query
                qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".")
                qtype_map = {1:"A", 28:"AAAA", 15:"MX", 2:"NS", 16:"TXT", 5:"CNAME"}
                qtype = qtype_map.get(dns[DNSQR].qtype, str(dns[DNSQR].qtype))
                self.queries[qname] += 1
                self.logger.info(f"[QUERY]  {src} -> {qname} ({qtype})")

            elif dns.qr == 1 and dns.haslayer(DNSRR):  # Response
                name = dns[DNSRR].rrname.decode(errors="ignore").rstrip(".")
                rdata = dns[DNSRR].rdata
                self.logger.success(f"[RESP]   {name} -> {rdata}")

    def run(self):
        self.logger.info(f"[*] DNS Monitor on {self.iface} | {self.count} packets")
        self.logger.warning("[!] Requires root/sudo")
        try:
            sniff(iface=self.iface, filter="udp port 53",
                  prn=self._process, count=self.count, store=False)

            self.logger.info(f"
--- Top DNS Queries ---")
            for domain, count in self.queries.most_common(10):
                self.logger.success(f"  {domain}: {count}x")

            # Detect suspicious domains
            suspicious = [d for d in self.queries if len(d) > 50 or d.count(".") > 5]
            if suspicious:
                self.logger.warning(f"⚠ Possible DNS tunneling detected:")
                for d in suspicious:
                    self.logger.warning(f"  {d}")
        except PermissionError:
            self.logger.error("Permission denied. Run with sudo.")
        except Exception as e:
            self.logger.error(f"DNS monitor error: {e}")
