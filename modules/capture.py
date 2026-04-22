#!/usr/bin/env python3
"""Packet Capture & Analysis Module"""
import struct, socket, time
from datetime import datetime

PROTOCOLS = {1:"ICMP", 6:"TCP", 17:"UDP"}

class PacketCapture:
    def __init__(self, iface, count, bpf_filter, save_file, logger):
        self.iface = iface
        self.count = count
        self.bpf_filter = bpf_filter
        self.save_file = save_file
        self.logger = logger
        self.packets = []

    def _parse_ethernet(self, raw):
        dst = ":".join(f"{b:02x}" for b in raw[:6])
        src = ":".join(f"{b:02x}" for b in raw[6:12])
        eth_type = struct.unpack("!H", raw[12:14])[0]
        return dst, src, eth_type, raw[14:]

    def _parse_ip(self, raw):
        ihl = (raw[0] & 0x0F) * 4
        proto = raw[9]
        src = socket.inet_ntoa(raw[12:16])
        dst = socket.inet_ntoa(raw[16:20])
        return src, dst, proto, raw[ihl:]

    def _parse_tcp(self, raw):
        src_port = struct.unpack("!H", raw[:2])[0]
        dst_port = struct.unpack("!H", raw[2:4])[0]
        flags = raw[13]
        flag_str = "".join([
            "SYN" if flags & 0x02 else "",
            "ACK" if flags & 0x10 else "",
            "FIN" if flags & 0x01 else "",
            "RST" if flags & 0x04 else "",
            "PSH" if flags & 0x08 else "",
        ])
        return src_port, dst_port, flag_str.strip() or "NONE"

    def _parse_udp(self, raw):
        src_port = struct.unpack("!H", raw[:2])[0]
        dst_port = struct.unpack("!H", raw[2:4])[0]
        return src_port, dst_port

    def run(self):
        self.logger.info(f"[*] Starting capture on {self.iface} ({self.count} packets)...")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            sock.bind((self.iface, 0))
        except PermissionError:
            self.logger.error("Permission denied — run with sudo")
            return
        except Exception as e:
            self.logger.error(f"Socket error: {e}")
            return

        captured = 0
        start = time.time()

        while captured < self.count:
            try:
                raw, _ = sock.recvfrom(65535)
                eth_dst, eth_src, eth_type, payload = self._parse_ethernet(raw)

                if eth_type == 0x0800:  # IPv4
                    ip_src, ip_dst, proto_num, data = self._parse_ip(payload)
                    proto = PROTOCOLS.get(proto_num, f"PROTO-{proto_num}")

                    if proto_num == 6:  # TCP
                        sp, dp, flags = self._parse_tcp(data)
                        self.logger.success(f"[TCP]  {ip_src}:{sp} -> {ip_dst}:{dp} [{flags}]")
                    elif proto_num == 17:  # UDP
                        sp, dp = self._parse_udp(data)
                        self.logger.info(f"[UDP]  {ip_src}:{sp} -> {ip_dst}:{dp}")
                    elif proto_num == 1:  # ICMP
                        self.logger.info(f"[ICMP] {ip_src} -> {ip_dst}")

                    self.packets.append({
                        "time": datetime.now().isoformat(),
                        "src": ip_src, "dst": ip_dst,
                        "protocol": proto, "size": len(raw)
                    })
                captured += 1
            except KeyboardInterrupt:
                break
            except Exception:
                continue

        elapsed = time.time() - start
        self.logger.info(f"[+] Captured {captured} packets in {elapsed:.1f}s")
        sock.close()
        return self.packets
