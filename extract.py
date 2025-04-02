import argparse
from scapy.all import rdpcap, Dot11, EAPOL

def extract_info(pcap_file):
    packets = rdpcap(pcap_file)
    ssid = ""
    bssid = ""
    ap_mac = ""
    sta_mac = ""
    key_mic = ""
    anonce = ""
    snonce = ""

    for pkt in packets:
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                ssid = pkt.info.decode()
                bssid = pkt.addr2
                ap_mac = pkt.addr2

            if pkt.type == 0 and pkt.subtype == 4:  # Probe request
                sta_mac = pkt.addr2

        if pkt.haslayer(EAPOL):
            eapol_pkt = pkt[EAPOL]
            if eapol_pkt.type == 3:  # Key message
                key_data = eapol_pkt.load
                if len(key_data) > 0:
                    key_mic = key_data[-16:]
                    if not anonce:
                        anonce = key_data[13:45]
                    if not snonce:
                        snonce = key_data[45:77]

    return ssid, bssid, ap_mac, sta_mac, key_mic, anonce, snonce

def main():
    parser = argparse.ArgumentParser(description='Extract WiFi handshake information from a pcap file.')
    parser.add_argument('pcap_file', help='The path to the pcap or .cap file')
    args = parser.parse_args()

    ssid, bssid, ap_mac, sta_mac, key_mic, anonce, snonce = extract_info(args.pcap_file)
    
    print(f'SSID: {ssid}')
    print(f'BSSID: {bssid}')
    print(f'AP MAC: {ap_mac}')
    print(f'STA MAC: {sta_mac}')
    print(f'Key MIC: {key_mic.hex()}')
    print(f'ANonce: {anonce.hex()}')
    print(f'SNonce: {snonce.hex()}')

if __name__ == '__main__':
    main()
