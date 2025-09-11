import os
os.environ["SCAPY_CACHE"] = r"C:\Users\suhas\scapy_cache"

from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to analyze each packet
def analyze_packet(packet):
    print("="*60)
    
    if packet.haslayer(IP):  # Check for IP packets
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol Num   : {ip_layer.proto}")

        # TCP packets
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol       : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        # UDP packets
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol       : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # Payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload (first 100 bytes): {payload[:100]}")
    else:
        print("Non-IP packet captured")

# Start sniffing
print("🚀 Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, count=10)  # Capture 10 packets (remove count for continuous capture)
