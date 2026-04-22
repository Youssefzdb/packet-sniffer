#!/usr/bin/env python3
"""Network Interface Lister"""
import subprocess, socket

def list_interfaces(logger):
    logger.info("Available network interfaces:")
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.splitlines():
            if ": " in line and not line.startswith(" "):
                parts = line.split(": ")
                if len(parts) >= 2:
                    name = parts[1].split("@")[0]
                    interfaces.append(name)
        for iface in interfaces:
            try:
                ip = socket.gethostbyname(socket.gethostname())
                logger.success(f"  [{iface}]")
            except:
                logger.success(f"  [{iface}]")
    except Exception:
        # Fallback
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get("addr", "no IP")
                logger.success(f"  {iface:15} -> {ip}")
        except:
            logger.warning("Could not enumerate interfaces. Try: ip link show")
