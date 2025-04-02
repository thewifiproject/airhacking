import argparse
from scapy.all import rdpcap, Dot11, EAPOL, Raw

def extract_handshake_info(pcap_file):
    try:
        # Read the pcap file
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading file {pcap_file}: {e}")
        return

    # Initialize variables
    message2 = None
    message3 = None
    ssid = None
    bssid = None
    ap_mac = None
    sta_mac = None
    anonce = None
    snonce = None
    key_mic = None

    # Iterate through packets
    for pkt in packets:
        # Check if packet is a Dot11 (Wi-Fi frame)
        if pkt.haslayer(Dot11):
            # Extract SSID and BSSID from Beacon frames
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame (SSID and BSSID)
                ssid = pkt.info.decode(errors='ignore')  # Extract SSID
                bssid = pkt.addr3  # BSSID is the AP MAC address

            # Check if packet has EAPOL layer (WPA handshake message)
            if pkt.haslayer(EAPOL):
                if pkt[Dot11].addr1 == bssid:  # Check for Message 2 (STA -> AP)
                    if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0x04:  # EAPOL frame
                        # Message 2 (STA -> AP) contains SNonce and MIC
                        message2 = pkt
                        sta_mac = pkt.addr2  # Client MAC address (STA)
                        if pkt.haslayer(Raw):
                            snonce = pkt[Raw].load[0:32]  # SNonce (first 32 bytes)
                            key_mic = pkt[Raw].load[32:48]  # Key MIC (next 16 bytes)

                # Check for Message 3 (AP -> STA)
                if pkt[Dot11].addr2 == bssid:  # Check for Message 3 (AP -> STA)
                    if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0x04:  # EAPOL frame
                        # Message 3 (AP -> STA) contains ANonce
                        message3 = pkt
                        if pkt.haslayer(Raw):
                            anonce = pkt[Raw].load[0:32]  # ANonce (first 32 bytes)

    # Output the collected information
    if message2 and message3:
        print("WPA Handshake Information Extracted:")
        print(f"SSID: {ssid}")
        print(f"BSSID (AP MAC): {bssid}")
        print(f"AP MAC: {ap_mac}")
        print(f"STA MAC (Client MAC): {sta_mac}")
        print(f"SNonce (from Message 2): {snonce.hex()}")
        print(f"ANonce (from Message 3): {anonce.hex()}")
        print(f"Key MIC (from Message 2): {key_mic.hex()}")
    else:
        print("Could not extract the required information from the handshake. Please check the pcap file for a complete WPA handshake (Message 2 and Message 3).")

if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Extract WPA Handshake Information from a .pcap file")
    parser.add_argument('pcap_file', metavar='file', type=str, help="Path to the .pcap file")
    args = parser.parse_args()

    # Extract information from the provided pcap file
    extract_handshake_info(args.pcap_file)
