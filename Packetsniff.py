from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def analyze_packet(packet):
    print("\n📦 Packet Captured:")
    print("-" * 60)
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol: TCP")
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
        else:
            print("Protocol: Other")

        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load
                printable_data = raw_data.decode(errors="ignore")
                print(f"Payload Data:\n{printable_data}")
            except Exception as e:
                print("Payload: <Non-decodable>")
    else:
        print("Non-IP Packet")

    print("-" * 60)

def start_sniffing(interface=None, count=10):
    print(f"🛡️  Starting Packet Sniffer on interface: {interface or 'default'}")
    sniff(iface=interface, prn=analyze_packet, count=count)

# Run the sniffer (Adjust interface and packet count as needed)
if __name__ == "__main__":
    # Replace 'eth0' with your interface name, or leave as None for default
    start_sniffing(interface=None, count=10)
