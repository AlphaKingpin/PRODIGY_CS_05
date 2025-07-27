# 🕵️‍♂️ Packet Sniffer with Scapy

This is a lightweight packet sniffer written in Python using the **Scapy** library. It captures and analyzes network packets, showing details such as source and destination IPs, protocols, and payload data.

## 📌 Features

- Captures both IP and non-IP packets.
- Displays:
  - Timestamp of capture
  - Source and destination IP addresses
  - Protocol used (TCP, UDP, or other)
  - Raw payload data (if available and decodable)
- Graceful handling of undecodable payloads.

## 🧰 Requirements

- Python 3.x
- Scapy library

> On Debian-based systems (like Kali Linux), you can install Scapy via:

```bash
sudo apt update
sudo apt install python3-scapy
```

Or install via pip:

```bash
pip install scapy
```

## 🚀 How to Run

1. Open a terminal.
2. Navigate to the project directory:

```bash
cd ~/Desktop/KEYLOGGER  # or wherever your file is located
```

3. Run the script with sudo (required for packet capturing):

```bash
sudo python3 packetsniff.py
```

## 📝 Script Explanation

### `analyze_packet(packet)`
- Checks if the packet is an IP packet.
- Extracts and displays IP addresses, protocol type, and payload (if available).

### `start_sniffing(interface=None, count=10)`
- Starts the packet sniffing process.
- Captures the specified number of packets (default = 10).
- You can change the interface or count as needed.

> Example (specifying interface):
```python
start_sniffing(interface="eth0", count=20)
```

## 📷 Sample Output

```
📦 Packet Captured:
------------------------------------------------------------
Time: 14:03:34
Source IP: 192.168.117.128
Destination IP: 239.255.255.250
Protocol: 17
Protocol: UDP
Payload Data:
<xml version="1.0"?><soap:Envelope xmlns:wsa=...
------------------------------------------------------------
```

## ⚠️ Disclaimer

This tool is meant for **educational and ethical use only**. Unauthorized packet sniffing may violate privacy laws or network policies.

## 👨‍💻 Author

- GitHub: https://github.com/AlphaKingpin/PRODIGY_CS_05
