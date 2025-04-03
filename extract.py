import sys
from scapy.all import *

def extract_mic_and_nonce(input_file):
    packets = rdpcap(input_file)
    
    snonce = None
    anonce = None

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            # Check if it's a Key (Message 2 of 4) or Message 3 of 4
            if eapol_layer.type == 3 and eapol_layer.key_mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    print(f"Extracted SNonce: {snonce.hex()}")
                return mic.hex()
            # Check if it's a Key (Message 3 of 4)
            elif eapol_layer.type == 3 and not eapol_layer.key_mic:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

    if not snonce:
        print("No SNonce found in Message 2 of 4.")
    if not anonce:
        print("No ANonce found in Message 3 of 4.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract.py <input_file.cap/pcap>")
        sys.exit(1)

    input_file = sys.argv[1]
    extract_mic_and_nonce(input_file)
