import sys
from scapy.all import *

def extract_mic_and_nonce(input_file):
    packets = rdpcap(input_file)
    
    snonce = None
    anonce = None
    mic = None
    sta_mac = None
    bssid = None
    ssid = None

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            # Check if it's a Key (Message 2 of 4)
            if eapol_layer.type == 3 and eapol_layer.key_mic and not mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    print(f"Extracted SNonce: {snonce.hex()}")
            # Check if it's a Key (Message 3 of 4)
            elif eapol_layer.type == 3 and not eapol_layer.key_mic and not anonce:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

            # Extract sta mac, bssid, and ssid
            if not sta_mac:
                sta_mac = packet.addr2
                print(f"Extracted STA MAC: {sta_mac}")
            if not bssid:
                bssid = packet.addr1
                print(f"Extracted BSSID: {bssid}")
            if not ssid and packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode()
                print(f"Extracted SSID: {ssid}")

            # Break the loop if all values are found
            if mic, snonce, anonce, sta_mac, bssid, ssid:
                break

    if not snonce:
        print("No SNonce found in Message 2 of 4.")
    if not anonce:
        print("No ANonce found in Message 3 of 4.")
    if not sta_mac:
        print("No STA MAC found.")
    if not bssid:
        print("No BSSID found.")
    if not ssid:
        print("No SSID found.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract.py <input_file.cap/pcap>")
        sys.exit(1)

    input_file = sys.argv[1]
    extract_mic_and_nonce(input_file)
