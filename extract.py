import argparse
from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11ProbeResp

def extract_info_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    key_mic, anonce, snonce, ssid, bssid, ap_mac, sta_mac = None, None, None, None, None, None, None

    for packet in packets:
        if packet.haslayer(EAPOL):
            # Extract BSSID and MAC addresses
            if packet.addr2 and packet.addr1:
                bssid = packet.addr3
                ap_mac = packet.addr2
                sta_mac = packet.addr1

            # Extract SSID from Beacon/Probe Response
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                ssid = packet.info.decode()

            # Extract Key MIC from Message 2 (when the load type is b'\x02')
            if packet[EAPOL].load[1:2] == b'\x02':
                key_mic = packet[EAPOL].load[81:97]  # Message 2 contains the Key MIC at the specified location
                snonce = packet[EAPOL].load[13:45]  # SNonce is in Message 2

            # Extract ANonce from Message 3 (when the load type is b'\x03')
            if packet[EAPOL].load[1:2] == b'\x03':
                anonce = packet[EAPOL].load[13:45]  # ANonce is in Message 3

    return key_mic, anonce, snonce, ssid, bssid, ap_mac, sta_mac

def main():
    parser = argparse.ArgumentParser(description="Extract WiFi handshake info from a pcap file.")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    args = parser.parse_args()

    key_mic, anonce, snonce, ssid, bssid, ap_mac, sta_mac = extract_info_from_pcap(args.pcap_file)

    print(f"SSID: {ssid}")
    print(f"BSSID: {bssid}")
    print(f"AP MAC: {ap_mac}")
    print(f"STA MAC: {sta_mac}")
    print(f"ANonce: {anonce.hex() if anonce else None}")
    print(f"SNonce: {snonce.hex() if snonce else None}")
    print(f"Key MIC: {key_mic.hex() if key_mic else None}")

if __name__ == "__main__":
    main()
