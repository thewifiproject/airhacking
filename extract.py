import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def to_hex(byte_string):
    if byte_string:
        return byte_string.hex()
    return None

def extract_info(pcap_file):
    packets = rdpcap(pcap_file)
    ssid = None
    bssid = None
    ap_mac = None
    sta_mac = None
    anonce = None
    snonce = None
    key_mic = None

    for packet in packets:
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ssid = packet.info.decode()
                bssid = packet.addr2
            elif packet.type == 2:  # Data frame
                if packet.addr1 and packet.addr2:
                    ap_mac = packet.addr1
                    sta_mac = packet.addr2

        if packet.haslayer(EAPOL):
            eapol = packet.getlayer(EAPOL)
            if eapol and eapol.type == 3:  # Key frame
                if not anonce and eapol.key_nonce:
                    anonce = eapol.key_nonce
                elif not snonce and eapol.key_nonce:
                    snonce = eapol.key_nonce
                if eapol.key_mic:
                    key_mic = eapol.key_mic

    print(f"SSID: {ssid}")
    print(f"BSSID: {bssid}")
    print(f"AP MAC: {ap_mac}")
    print(f"STA MAC: {sta_mac}")
    print(f"ANonce: {to_hex(anonce)}")
    print(f"SNonce: {to_hex(snonce)}")
    print(f"Key MIC: {to_hex(key_mic)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract WPA handshake information from a PCAP file")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    args = parser.parse_args()

    extract_info(args.pcap_file)
