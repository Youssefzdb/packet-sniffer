#!/usr/bin/env python3
"""HTTP Traffic Sniffer"""
import socket, struct, re

HTTP_METHODS = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"PATCH ", b"OPTIONS "]

class HTTPSniffer:
    def __init__(self, iface, count, logger):
        self.iface = iface
        self.count = count
        self.logger = logger
        self.requests = []

    def _parse_http(self, payload):
        try:
            for method in HTTP_METHODS:
                if payload.startswith(method):
                    lines = payload.decode(errors="ignore").splitlines()
                    request_line = lines[0]
                    headers = {}
                    for line in lines[1:]:
                        if ": " in line:
                            k, v = line.split(": ", 1)
                            headers[k] = v
                        elif line == "":
                            break
                    return {
                        "request": request_line,
                        "host": headers.get("Host", "?"),
                        "user_agent": headers.get("User-Agent", "?")[:80]
                    }
        except:
            pass
        return None

    def run(self):
        self.logger.info(f"[*] HTTP Sniffer on {self.iface}...")
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
                ip_proto = raw[23]
                if ip_proto != 6: continue  # TCP only
                ihl = (raw[14] & 0x0F) * 4
                ip_start = 14
                tcp_start = ip_start + ihl
                dst_port = struct.unpack("!H", raw[tcp_start+2:tcp_start+4])[0]
                src_port = struct.unpack("!H", raw[tcp_start:tcp_start+2])[0]
                if dst_port not in [80, 8080] and src_port not in [80, 8080]:
                    continue
                data_offset = (raw[tcp_start+12] >> 4) * 4
                payload = raw[tcp_start + data_offset:]
                if not payload: continue
                result = self._parse_http(payload)
                if result:
                    src_ip = socket.inet_ntoa(raw[26:30])
                    self.logger.success(f"[HTTP] {src_ip}:{src_port} -> {result['host']}")
                    self.logger.info(f"       {result['request']}")
                    if result["user_agent"] != "?":
                        self.logger.info(f"       UA: {result['user_agent']}")
                    self.requests.append(result)
                seen += 1
            except KeyboardInterrupt:
                break
            except:
                continue
        sock.close()
        return self.requests
