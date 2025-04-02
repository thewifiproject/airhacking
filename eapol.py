import argparse
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Elt

def extract_eapol_info(pcap_file):
    packets = rdpcap(pcap_file)
    networks = {}

    for pkt in packets:
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr2
                if bssid not in networks:
                    networks[bssid] = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'ap_mac': bssid,
                        'sta_mac': None,
                        'anonce': None,
                        'snonce': None,
                        'key_mic': None
                    }
        if pkt.haslayer(EAPOL):
            eapol = pkt[EAPOL]
            if hasattr(eapol, 'type') and eapol.type == 3:  # EAPOL Key
                bssid = pkt[Dot11].addr2
                sta_mac = pkt[Dot11].addr1
                if bssid in networks:
                    networks[bssid]['sta_mac'] = sta_mac
                    if hasattr(eapol.payload, 'key_info'):
                        print(f"Found EAPOL Key Info: {eapol.payload.key_info}")
                        if eapol.payload.key_info & 0x8:  # Message 2
                            networks[bssid]['snonce'] = eapol.payload.load[13:45].hex()
                            networks[bssid]['key_mic'] = eapol.payload.load[77:93].hex()
                            print(f"Extracted SNonce: {networks[bssid]['snonce']}, Key MIC: {networks[bssid]['key_mic']}")
                        if eapol.payload.key_info & 0x1:  # Message 3
                            networks[bssid]['anonce'] = eapol.payload.load[13:45].hex()
                            print(f"Extracted ANonce: {networks[bssid]['anonce']}")

    # If more than 2 networks are found, prompt the user to select one
    if len(networks) > 2:
        print("Multiple networks found. Please select one:")
        for i, (bssid, info) in enumerate(networks.items()):
            print(f"{i}: SSID: {info['ssid']}, BSSID: {info['bssid']}")
        selected_index = int(input("Enter the number of the network to select: "))
        selected_network = list(networks.values())[selected_index]
    else:
        selected_network = list(networks.values())[0]

    return selected_network

def main():
    parser = argparse.ArgumentParser(description="Extract EAPOL information from a pcap file")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    args = parser.parse_args()

    network_info = extract_eapol_info(args.pcap_file)
    print("Extracted Information:")
    print(f"SSID: {network_info['ssid']}")
    print(f"BSSID: {network_info['bssid']}")
    print(f"AP MAC: {network_info['ap_mac']}")
    print(f"STA MAC: {network_info['sta_mac']}")
    print(f"ANonce: {network_info['anonce']}")
    print(f"SNonce: {network_info['snonce']}")
    print(f"Key MIC: {network_info['key_mic']}")

if __name__ == "__main__":
    main()
