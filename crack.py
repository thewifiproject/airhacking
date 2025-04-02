import argparse
import binascii
import scapy.all as scapy

def extract_pmkid(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(scapy.EAPOL):
            # Check if this packet contains the PMKID in the RSN information element
            raw = packet[scapy.EAPOL].original
            if len(raw) >= 100:
                pmkid = raw[-20:-4]
                ap_mac = packet.addr2.replace(':', '') if isinstance(packet.addr2, str) else binascii.hexlify(packet.addr2).decode()
                sta_mac = packet.addr1.replace(':', '') if isinstance(packet.addr1, str) else binascii.hexlify(packet.addr1).decode()
                return pmkid.hex(), ap_mac, sta_mac
    return None, None, None

def main():
    parser = argparse.ArgumentParser(description='PMKID extraction tool')
    parser.add_argument('pcap_file', help='Path to the .cap or .pcap file')
    args = parser.parse_args()

    pcap_file = args.pcap_file

    pmkid, ap_mac, sta_mac = extract_pmkid(pcap_file)
    if pmkid is None:
        print("PMKID not found in the capture file")
        return

    print(f"Extracted PMKID: {pmkid}")
    print(f"AP MAC: {ap_mac}")
    print(f"STA MAC: {sta_mac}")

if __name__ == "__main__":
    main()
