#!/usr/bin/env python3
"""HTTP Traffic Parser & Credential Detector"""
from scapy.all import sniff, IP, TCP, Raw
import re

class HTTPParser:
    def __init__(self, iface, count, logger):
        self.iface = iface
        self.count = count
        self.logger = logger
        self.requests = []

    def _process(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        raw = pkt[Raw].load
        try:
            decoded = raw.decode("utf-8", errors="ignore")
        except:
            return

        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
        dport = pkt[TCP].dport

        # HTTP Request
        if decoded.startswith(("GET","POST","PUT","DELETE","HEAD","PATCH")):
            lines = decoded.split("\r\n")
            method_line = lines[0]
            host = next((l.split(": ",1)[1] for l in lines if l.startswith("Host:")), dst)
            self.logger.success(f"[HTTP] {src} -> {host} | {method_line[:80]}")

            # Detect credentials in POST
            if decoded.startswith("POST"):
                cred_patterns = [
                    (r"(?i)(password|passwd|pass|pwd)=([^&\s]+)", "PASSWORD"),
                    (r"(?i)(username|user|login|email)=([^&\s]+)", "USERNAME"),
                    (r"(?i)(token|api_key|apikey|secret)=([^&\s]+)", "TOKEN"),
                ]
                body = decoded.split("\r\n\r\n", 1)[-1]
                for pattern, label in cred_patterns:
                    for match in re.finditer(pattern, body):
                        self.logger.warning(f"⚠ [{label}] {match.group(1)}={match.group(2)[:30]}...")

        # HTTPS detection
        elif dport == 443:
            self.logger.info(f"[HTTPS] {src} -> {dst}:443 (encrypted)")

    def run(self):
        self.logger.info(f"[*] HTTP Parser on {self.iface}")
        self.logger.warning("[!] Only captures cleartext HTTP (port 80). HTTPS is encrypted.")
        self.logger.warning("[!] Requires root/sudo")
        try:
            sniff(iface=self.iface, filter="tcp port 80 or tcp port 443",
                  prn=self._process, count=self.count, store=False)
        except PermissionError:
            self.logger.error("Permission denied. Run with sudo.")
        except Exception as e:
            self.logger.error(f"HTTP parser error: {e}")
