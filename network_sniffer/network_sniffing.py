from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

def analyze_packet(packet):
    print("\n--- Packet Captured ---")
    print(f"Time: {datetime.datetime.now()}")

    # Check if IP layer exists
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}", end=" ")

        # Detect common protocols
        if ip_layer.proto == 6:
            print("(TCP)")
        elif ip_layer.proto == 17:
            print("(UDP)")
        elif ip_layer.proto == 1:
            print("(ICMP)")
        else:
            print("(Unknown)")

    # Extract TCP or UDP ports
    if TCP in packet:
        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        print(f"Source Port    : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    # Show raw payload
    if Raw in packet:
        raw_data = packet[Raw].load
        try:
            print(f"Payload (raw)  : {raw_data.decode(errors='ignore')}")
        except:
            print("Payload        : [Binary Data]")

def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()
