import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11AssoReq, Dot11ReassocReq, Dot11Elt

def extract_info(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)
    
    key_mic = None
    anonce = None
    snonce = None
    ssid = None
    bssid = None
    ap_mac = None
    sta_mac = None

    for packet in packets:
        if packet.haslayer(Dot11):
            # Extract the SSID and BSSID from Beacon frames or Probe responses
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ssid = packet[Dot11Elt].info.decode() if packet.haslayer(Dot11Elt) else None
                bssid = packet[Dot11].addr3

            # Look for Message 2 and Message 3 (RSN info for WPA handshake)
            if packet.haslayer(Dot11Auth):
                if packet[Dot11Auth].algorithm == 0:  # Open System Auth (for WPA handshake)
                    if packet[Dot11Auth].seqnum == 2:  # Message 2
                        snonce = packet[Dot11Auth].nonce
                        sta_mac = packet[Dot11].addr2
                        ap_mac = packet[Dot11].addr1
                    elif packet[Dot11Auth].seqnum == 3:  # Message 3
                        anonce = packet[Dot11Auth].nonce
                        key_mic = packet[Dot11Auth].keymic

    return key_mic, anonce, snonce, ssid, bssid, ap_mac, sta_mac

def main():
    parser = argparse.ArgumentParser(description='Extract WPA handshake information from a pcap or .cap file')
    parser.add_argument('file', help='Path to the pcap or .cap file')
    args = parser.parse_args()

    key_mic, anonce, snonce, ssid, bssid, ap_mac, sta_mac = extract_info(args.file)

    # Print out the extracted information
    print("Key MIC: ", key_mic)
    print("ANonce: ", anonce)
    print("SNonce: ", snonce)
    print("SSID: ", ssid)
    print("BSSID: ", bssid)
    print("AP MAC: ", ap_mac)
    print("STA MAC (Client MAC): ", sta_mac)

if __name__ == "__main__":
    main()
