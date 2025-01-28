from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Other"
        
        # Determine the protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")
        print("-" * 50)

def main():
    print("Starting packet capture...")
    print("Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
