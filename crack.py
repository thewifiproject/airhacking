import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def extract_pmkid(pcap_file):
    packets = rdpcap(pcap_file)
    
    for pkt in packets:
        if pkt.haslayer(Dot11):
            if pkt.haslayer(EAPOL):
                if len(pkt) >= 0x76:
                    ap_mac = pkt.addr2.replace(':', '') if pkt.addr2 else None
                    sta_mac = pkt.addr1.replace(':', '') if pkt.addr1 else None
                    pmkid = pkt.load[-16:].hex() if hasattr(pkt, 'load') else None
                    
                    if ap_mac and sta_mac and pmkid:
                        print(f"AP MAC: {ap_mac}")
                        print(f"STA MAC: {sta_mac}")
                        print(f"PMKID: {pmkid}")
                        print("-")
                        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract PMKID, AP MAC, and STA MAC from a capture file.")
    parser.add_argument("capture", help="Path to the capture file (.pcap or .pcapng)")
    args = parser.parse_args()
    
    extract_pmkid(args.capture)
