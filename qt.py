import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def extract_pmkid(pcap_file):
    packets = rdpcap(pcap_file)
    pmkid_list = []
    
    for pkt in packets:
        if pkt.haslayer(Dot11):
            ap_mac = pkt.addr2  # AP MAC Address
            sta_mac = pkt.addr1  # STA MAC Address
            
            if pkt.haslayer(EAPOL):
                raw_data = bytes(pkt)
                if len(raw_data) >= 0x76:  # Checking for PMKID presence
                    pmkid = raw_data[-16:].hex()
                    pmkid_list.append((ap_mac, sta_mac, pmkid))
    
    if not pmkid_list:
        print("No PMKID found in the capture file.")
    else:
        for ap, sta, pmkid in pmkid_list:
            print(f"AP MAC: {ap} | STA MAC: {sta} | PMKID: {pmkid}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract PMKID, AP MAC, and STA MAC from a capture file.")
    parser.add_argument("capture", help="Path to the capture file")
    args = parser.parse_args()
    extract_pmkid(args.capture)
