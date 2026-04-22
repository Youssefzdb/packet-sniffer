#!/usr/bin/env python3
"""DNS Traffic Monitor"""
import socket, struct
from datetime import datetime

class DNSMonitor:
    def __init__(self, iface, count, logger):
        self.iface = iface
        self.count = count
        self.logger = logger
        self.queries = []

    def _parse_dns_name(self, data, offset):
        parts = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:  # Pointer
                ptr = ((length & 0x3F) << 8) | data[offset+1]
                name, _ = self._parse_dns_name(data, ptr)
                parts.append(name)
                offset += 2
                break
            else:
                offset += 1
                parts.append(data[offset:offset+length].decode(errors="ignore"))
                offset += length
        return ".".join(parts), offset

    def _parse_dns(self, data):
        try:
            txid = struct.unpack("!H", data[:2])[0]
            flags = struct.unpack("!H", data[2:4])[0]
            qdcount = struct.unpack("!H", data[4:6])[0]
            is_response = (flags >> 15) & 1
            offset = 12
            if qdcount > 0 and offset < len(data):
                name, offset = self._parse_dns_name(data, offset)
                qtype = struct.unpack("!H", data[offset:offset+2])[0]
                types = {1:"A", 2:"NS", 5:"CNAME", 15:"MX", 16:"TXT", 28:"AAAA"}
                return {
                    "type": "RESPONSE" if is_response else "QUERY",
                    "txid": hex(txid),
                    "name": name,
                    "qtype": types.get(qtype, str(qtype))
                }
        except:
            pass
        return None

    def run(self):
        self.logger.info(f"[*] DNS Monitor on {self.iface} ({self.count} packets)...")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            sock.bind((self.iface, 0))
        except PermissionError:
            self.logger.error("Run with sudo")
            return

        seen = 0
        while seen < self.count:
            try:
                raw, _ = sock.recvfrom(65535)
                # Parse IP header
                ip_proto = raw[23]
                if ip_proto != 17: continue  # UDP only
                ihl = (raw[14] & 0x0F) * 4
                ip_start = 14 + ihl
                src_ip = socket.inet_ntoa(raw[26:30])
                udp_data = raw[ip_start+8:]
                dst_port = struct.unpack("!H", raw[ip_start+2:ip_start+4])[0]
                src_port = struct.unpack("!H", raw[ip_start:ip_start+2])[0]
                if dst_port != 53 and src_port != 53:
                    continue
                result = self._parse_dns(udp_data)
                if result:
                    direction = "→" if result["type"] == "QUERY" else "←"
                    self.logger.success(f"[DNS {direction}] [{result['qtype']}] {result['name']} (txid:{result['txid']})")
                    self.queries.append(result)
                seen += 1
            except KeyboardInterrupt:
                break
            except:
                continue
        sock.close()
        return self.queries
