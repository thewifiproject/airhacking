import sys
from scapy.all import *

def extract_mic(input_file):
    packets = rdpcap(input_file)
    
    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            # Check if it's a Key (Message 2 of 4)
            if eapol_layer.type == 3 and eapol_layer.key_mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                return mic.hex()

    print("No EAPOL Message 2 of 4 Key found.")
    return None

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract.py <input_file.cap/pcap>")
        sys.exit(1)

    input_file = sys.argv[1]
    extract_mic(input_file)
