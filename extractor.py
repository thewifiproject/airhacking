import argparse
from scapy.all import rdpcap, Dot11, Dot11Beacon, EAPOL

def extract_info(pcap_file):
    packets = rdpcap(pcap_file)
    networks = {}
    
    for packet in packets:
        if packet.haslayer(Dot11):
            ssid = packet.info.decode() if packet.haslayer(Dot11Beacon) else None
            bssid = packet.addr2
            if ssid and bssid:
                if bssid not in networks:
                    networks[bssid] = {
                        'SSID': ssid,
                        'AP_MAC': bssid,
                        'clients': set(),
                        'ANonce': None,
                        'SNonce': None,
                        'KeyMIC': None,
                    }
    
    for packet in packets:
        if packet.haslayer(EAPOL):
            if packet.type == 0 and packet.subtype == 0:
                continue  # Ignore non-EAPOL packets
            eapol_payload = bytes(packet[EAPOL].payload)
            bssid = packet.addr2
            sta_mac = packet.addr1
            if bssid in networks:
                networks[bssid]['clients'].add(sta_mac)
                if packet[EAPOL].type == 3:
                    networks[bssid]['ANonce'] = eapol_payload[13:45].hex()
                if packet[EAPOL].type == 2:  # Message 2 of the 4-Way Handshake
                    networks[bssid]['SNonce'] = eapol_payload[51:83].hex()
                    networks[bssid]['KeyMIC'] = eapol_payload[77:93].hex()
    
    return networks

def main():
    parser = argparse.ArgumentParser(description="Extract EAPOL information from a pcap file.")
    parser.add_argument("pcap_file", help="The path to the pcap file.")
    args = parser.parse_args()

    networks = extract_info(args.pcap_file)
    
    if len(networks) > 1:
        print("More than one network detected. Please specify the BSSID of the network to analyze:")
        for i, bssid in enumerate(networks):
            print(f"{i + 1}. SSID: {networks[bssid]['SSID']}, BSSID: {bssid}")
        choice = int(input("Select network (number): ")) - 1
        bssid = list(networks.keys())[choice]
        network = networks[bssid]
    else:
        bssid = list(networks.keys())[0]
        network = networks[bssid]

    print(f"SSID: {network['SSID']}")
    print(f"BSSID: {bssid}")
    print(f"AP MAC: {network['AP_MAC']}")
    print("Clients:")
    for client in network['clients']:
        print(f" - {client}")
    print(f"ANonce: {network['ANonce']}")
    print(f"SNonce: {network['SNonce']}")
    print(f"Key MIC: {network['KeyMIC']}")

if __name__ == "__main__":
    main()
