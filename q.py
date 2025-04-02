import argparse
from scapy.all import rdpcap, Dot11Beacon, Dot11, Dot11Elt

def extract_pmkid(pcap_file):
    packets = rdpcap(pcap_file)
    pmkid_list = []
    
    for pkt in packets:
        if pkt.haslayer(Dot11):
            if pkt.haslayer(Dot11Beacon) or (pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8):
                ap_mac = pkt.addr2  # AP MAC Address
            
            if pkt.haslayer(Dot11Elt) and pkt.type == 2 and pkt.subtype == 0:
                sta_mac = pkt.addr1  # STA MAC Address
                
                raw_data = bytes(pkt)
                if len(raw_data) >= 86:  # Check for PMKID existence
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
