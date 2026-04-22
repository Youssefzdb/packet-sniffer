#!/usr/bin/env python3
"""Traffic Statistics Module"""
import socket, struct, time
from collections import defaultdict

class TrafficStats:
    def __init__(self, iface, count, interval, logger):
        self.iface = iface
        self.count = count
        self.interval = interval
        self.logger = logger
        self.proto_count = defaultdict(int)
        self.ip_count = defaultdict(int)
        self.total_bytes = 0
        self.start = time.time()

    PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def _print_stats(self):
        elapsed = time.time() - self.start
        self.logger.success(f"
{'='*50}")
        self.logger.success(f"  Traffic Stats ({elapsed:.0f}s)")
        self.logger.success(f"  Total Bytes : {self.total_bytes:,}")
        self.logger.success(f"  Throughput  : {self.total_bytes/elapsed/1024:.2f} KB/s")
        self.logger.success(f"
  Protocol Breakdown:")
        for proto, count in sorted(self.proto_count.items(), key=lambda x:-x[1]):
            self.logger.info(f"    {proto:<8} {count:>6} packets")
        self.logger.success(f"
  Top Talkers:")
        top = sorted(self.ip_count.items(), key=lambda x:-x[1])[:5]
        for ip, count in top:
            self.logger.info(f"    {ip:<20} {count:>6} packets")
        self.logger.success(f"{'='*50}")

    def run(self):
        self.logger.info(f"[*] Traffic Stats on {self.iface} (interval: {self.interval}s)")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            sock.bind((self.iface, 0))
        except PermissionError:
            self.logger.error("Run with sudo")
            return

        last_print = time.time()
        seen = 0
        while seen < self.count:
            try:
                raw, _ = sock.recvfrom(65535)
                self.total_bytes += len(raw)
                if len(raw) > 23:
                    ip_proto = raw[23]
                    proto_name = self.PROTOCOLS.get(ip_proto, f"OTHER({ip_proto})")
                    self.proto_count[proto_name] += 1
                    if len(raw) >= 30:
                        src_ip = socket.inet_ntoa(raw[26:30])
                        self.ip_count[src_ip] += 1
                seen += 1
                if time.time() - last_print >= self.interval:
                    self._print_stats()
                    last_print = time.time()
            except KeyboardInterrupt:
                break
            except:
                continue
        sock.close()
        self._print_stats()
