#!/usr/bin/env python3
"""ARP Spoofing Detection Module"""
import socket, struct
from datetime import datetime

class ARPWatch:
    def __init__(self, iface, count, logger):
        self.iface = iface
        self.count = count
        self.logger = logger
        self.arp_table = {}  # {ip: mac}
        self.alerts = []

    def _parse_arp(self, raw):
        # ARP Packet: starts after Ethernet header (14 bytes)
        if len(raw) < 28:
            return None
        hw_type = struct.unpack("!H", raw[14:16])[0]
        proto_type = struct.unpack("!H", raw[16:18])[0]
        op = struct.unpack("!H", raw[20:22])[0]
        sender_mac = ":".join(f"{b:02x}" for b in raw[22:28])
        sender_ip = socket.inet_ntoa(raw[28:32])
        target_ip = socket.inet_ntoa(raw[38:42])
        return {
            "op": "REQUEST" if op == 1 else "REPLY",
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_ip": target_ip
        }

    def _detect_spoofing(self, arp):
        ip = arp["sender_ip"]
        mac = arp["sender_mac"]
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                alert = {
                    "time": datetime.now().isoformat(),
                    "type": "ARP_SPOOFING",
                    "ip": ip,
                    "old_mac": self.arp_table[ip],
                    "new_mac": mac
                }
                self.alerts.append(alert)
                self.logger.warning(f"⚠️  ARP SPOOFING DETECTED!")
                self.logger.warning(f"   IP: {ip}")
                self.logger.warning(f"   Old MAC: {self.arp_table[ip]}")
                self.logger.warning(f"   New MAC: {mac}")
        else:
            self.arp_table[ip] = mac

    def run(self):
        self.logger.info(f"[*] ARP Watch on {self.iface} — monitoring for spoofing...")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((self.iface, 0))
        except PermissionError:
            self.logger.error("Run with sudo")
            return
        except Exception as e:
            self.logger.error(f"Socket error: {e}")
            return

        seen = 0
        while seen < self.count:
            try:
                raw, _ = sock.recvfrom(65535)
                arp = self._parse_arp(raw)
                if arp:
                    op_icon = "?" if arp["op"] == "REQUEST" else "!"
                    self.logger.info(f"[ARP {op_icon}] {arp['sender_ip']} ({arp['sender_mac']}) -> {arp['target_ip']}")
                    self._detect_spoofing(arp)
                seen += 1
            except KeyboardInterrupt:
                break
            except:
                continue
        sock.close()
        self.logger.info(f"[+] Done. {len(self.alerts)} spoofing alerts detected.")
        return self.alerts
