import sys
import argparse
import scapy.all as scapy

def read_pcap(file_path):
    """Read the pcap file and return the packets."""
    try:
        packets = scapy.rdpcap(file_path)
        return packets
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        sys.exit(1)

def extract_macs(packets):
    """Extract AP MAC and client source MAC from packets."""
    ap_mac = None
    client_mac = None
    for packet in packets:
        if packet.haslayer(scapy.Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ap_mac = packet.addr2
            elif packet.type == 2:  # Data frame
                client_mac = packet.addr1
        if ap_mac and client_mac:
            break
    return ap_mac, client_mac

def send_packets(packets, interface):
    """Send packets over the specified network interface."""
    try:
        scapy.sendp(packets, iface=interface, verbose=False)
        print(f"Packets sent successfully over interface {interface}")
    except Exception as e:
        print(f"Error sending packets: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Send pcap file contents over a network")
    parser.add_argument("-r", "--read", required=True, help="File to read (inject)")
    parser.add_argument("interface", help="Network interface to send packets")

    args = parser.parse_args()

    file_path = args.read
    interface = args.interface

    if not (file_path.endswith('.cap') or file_path.endswith('.pcap') or file_path.endswith('.pcapng')):
        print("Unsupported file format. Only .cap, .pcap, and .pcapng are supported.")
        sys.exit(1)

    packets = read_pcap(file_path)
    ap_mac, client_mac = extract_macs(packets)

    if not ap_mac or not client_mac:
        print("Alert: AP MAC or client source MAC not found in the pcap file.")
        sys.exit(1)

    print(f"AP MAC: {ap_mac}, Client MAC: {client_mac}")
    send_packets(packets, interface)

if __name__ == "__main__":
    main()
