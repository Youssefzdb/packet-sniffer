# 🌐 PacketSniffer

> Network Packet Capture & Protocol Analysis Tool | by **Shadow Core**

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python) ![Scapy](https://img.shields.io/badge/Scapy-2.5+-green) ![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## Features
- 📡 **Live Capture** — Capture packets on any interface with BPF filters
- 🔬 **PCAP Analyzer** — Protocol stats, top IPs, anomaly detection
- 🌍 **DNS Monitor** — Real-time DNS query tracking + tunneling detection
- 🌐 **HTTP Parser** — Capture HTTP traffic + credential detection in POST

## Installation

```bash
git clone https://github.com/Youssefzdb/packet-sniffer
cd packet-sniffer
pip install -r requirements.txt
```

## Usage

```bash
# Live capture (100 packets)
sudo python3 main.py sniff --iface eth0 --count 100 --output capture.pcap

# Analyze pcap file
python3 main.py analyze --file capture.pcap --proto tcp

# Monitor DNS queries
sudo python3 main.py dns --iface eth0 --count 50

# Capture HTTP traffic
sudo python3 main.py http --iface eth0 --count 50
```

## ⚠️ Disclaimer
For authorized network monitoring only. Always obtain proper permission.

## 👤 Author
**Shadow Core** | Network Security Researcher
