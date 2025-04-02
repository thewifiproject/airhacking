import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def extract_pmkid(capture_file):
    packets = rdpcap(capture_file)

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            try:
                if eapol_layer.load:
                    pmkid = eapol_layer.load.hex()
                    ap_mac = packet.addr2 if packet.addr2 else "Unknown"
                    sta_mac = packet.addr1 if packet.addr1 else "Unknown"
                    print(f"PMKID: {pmkid}")
                    print(f"AP MAC: {ap_mac}")
                    print(f"STA MAC: {sta_mac}")
            except AttributeError:
                continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract PMKID, AP MAC, and STA MAC from capture file")
    parser.add_argument("capture", help="Path to the capture file")
    args = parser.parse_args()

    extract_pmkid(args.capture)
