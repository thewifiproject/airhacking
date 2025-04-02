import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def extract_info(pcap_file):
    packets = rdpcap(pcap_file)
    ssid = None
    bssid = None
    anonce = None
    snonce = None
    key_mic = None
    ap_mac = None
    sta_mac = None

    for packet in packets:
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ssid = packet.info.decode()
                bssid = packet.addr2
            elif packet.type == 0 and packet.subtype == 0:  # Association request
                sta_mac = packet.addr2
            elif packet.type == 0 and packet.subtype == 4:  # Probe request
                ap_mac = packet.addr2

        if packet.haslayer(EAPOL):
            eapol = packet.getlayer(EAPOL)
            try:
                if hasattr(eapol, 'key_info'):
                    print(f"EAPOL key_info: {eapol.key_info}")
                    if eapol.key_info & 0x8:  # Check if it is message 3
                        print(f"Found ANonce in EAPOL message: {eapol.nonce}")
                        anonce = eapol.nonce
                    else:  # Otherwise it is message 2
                        print(f"Found SNonce in EAPOL message: {eapol.nonce}")
                        snonce = eapol.nonce
                        key_mic = eapol.key_mic
            except AttributeError as e:
                print(f"AttributeError: {e} - This packet may not have the required fields.")

    print(f"SSID: {ssid}")
    print(f"BSSID: {bssid}")
    print(f"ANonce: {anonce}")
    print(f"SNonce: {snonce}")
    print(f"Key MIC: {key_mic}")
    print(f"AP MAC: {ap_mac}")
    print(f"STA MAC: {sta_mac}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract information from a pcap file")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    args = parser.parse_args()

    extract_info(args.pcap_file)
