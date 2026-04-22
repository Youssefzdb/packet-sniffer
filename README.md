# 🦈 ShadowSniffer — Network Packet Analyzer

> Advanced Packet Capture & Protocol Analysis Tool | by **Shadow Core**

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)

```
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

## 🔍 Features

- **Live Packet Capture** — Capture packets on any network interface
- **Protocol Analysis** — TCP, UDP, ICMP, DNS, HTTP, ARP
- **Traffic Statistics** — Real-time bandwidth, protocol breakdown
- **DNS Monitor** — Watch DNS queries & responses live
- **HTTP Sniffer** — Extract HTTP methods, URLs, headers
- **ARP Watch** — Detect ARP spoofing & poisoning attempts
- **PCAP Export** — Save captures in PCAP format
- **JSON Reports** — Export analysis results

## 🚀 Installation

```bash
git clone https://github.com/Youssefzdb/packet-sniffer
cd packet-sniffer
pip install -r requirements.txt
```

## ⚡ Usage

```bash
# List network interfaces
sudo python3 main.py interfaces

# Capture all packets on eth0
sudo python3 main.py capture --iface eth0 --count 100

# Monitor DNS traffic only
sudo python3 main.py dns --iface eth0

# Sniff HTTP traffic
sudo python3 main.py http --iface eth0

# Watch for ARP spoofing
sudo python3 main.py arp --iface eth0

# Live traffic stats
sudo python3 main.py stats --iface eth0 --interval 5
```

## ⚠️ Disclaimer

> Requires root/admin privileges. Only capture traffic on networks you own or have explicit permission to monitor.

## 👤 Author

**Shadow Core** | Network Security Researcher
