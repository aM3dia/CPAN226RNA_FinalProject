"""
Raw Packet Sniffer & Protocol Analyzer
Anupa Ragoonanan (n01423202)
CPAN 226 RNA
April 17, 2026
"""

# import scapy if not available
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("!"*60)
    print("\nScapy library is required.")
    print("Install it using: pip3 install scapy")
    print("Then run with administrator privileges:")
    print("Windows: Run as Administrator")
    print("Linux/macOS: sudo python3 sniffer.py")
    print("!"*60)
    exit(1)

# global packet counter
packet_count = 0

# process packet
def process_packet(packet):
    """process captured packet"""
    global packet_count
    packet_count += 1
    
    print(f"\n{'='*60}")
    print(f"PACKET #{packet_count}")
    print(f"{'='*60}")
    
    # Ethernet
    if Ether in packet:
        eth = packet[Ether]
        print(f"\nEthernet:")
        print(f"Source: {eth.src}")
        print(f"Destination: {eth.dst}")
    else:
        print(f"Ethernet:")
        print(f"Source: [Not available]")
        print(f"Destination: [Not available]")
    
    # Internet Protocol (IP)
    if IP in packet:
        ip = packet[IP]
        print(f"\nInternet Protocol:")
        print(f"Version: {ip.version}")
        print(f"TTL: {ip.ttl}")
        print(f"Source: {ip.src}")
        print(f"Destination: {ip.dst}")
        
        # Transport Control Protocol (TCP)
        if TCP in packet:
            tcp = packet[TCP]
            print(f"\nTransport Control Protocol:")
            print(f"Source Port: {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")
            print(f"Sequence: {tcp.seq}")
            print(f"Acknowledgment: {tcp.ack}")
            print(f"Length: {tcp.len}")
            
            # show payload if present
            if tcp.payload and len(bytes(tcp.payload)) > 0:
                payload = bytes(tcp.payload)
                print(f"\nPayload: {len(payload)} bytes")
        
        # User Datagram Protocol (UDP)
        elif UDP in packet:
            udp = packet[UDP]
            print(f"\nUser Datagram Protocol:")
            print(f"Source Port: {udp.sport}")
            print(f"Destination Port: {udp.dport}")
            
            # show payload if present
            if udp.payload and len(bytes(udp.payload)) > 0:
                payload = bytes(udp.payload)
                print(f"\nPayload: {len(payload)} bytes")

# main function
def main():
    global packet_count
    
    print(f"\nStarting packet sniffer... Press Ctrl+C to stop.")
        
    # start capturing packets
    try:
        # function to call for each packet, don't store packets in memory, and capture a limit of 15 packets
        sniff(prn=process_packet, store=False, count=15)
        
    except PermissionError:
        print("\n" + "!"*60)
        print("ERROR: Permission denied! Need administrator/root privileges.")
        print("\nRun with:")
        print("Windows: Right-click Command Prompt/PowerShell → Run as Administrator")
        print("Linux/macOS: sudo python3 sniffer.py")
        print("!"*60)
        
    except KeyboardInterrupt:
            # display summary when user stops the sniffer with Ctrl+C
            pass
    # display summary when sniffer completes 15 packets 
    print("\n" + "="*60)
    print(f"Sniffer stopped.")
    print(f"Total packets captured: {packet_count}")
    print()

if __name__ == "__main__":
    main()