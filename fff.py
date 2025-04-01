from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11WEP, Dot11TKIP, EAPOL

def extract_wpa_key_mic(packet):
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key
            key_descriptor = eapol.payload.fields_desc[0].default
            if key_descriptor == 2:  # RSN Key Descriptor
                key_mic = eapol.payload.fields_desc[13].default
                print(f"WPA Key MIC: {key_mic}")

def main():
    pcap_file = "wpa.cap"
    packets = rdpcap(pcap_file)
    for pkt in packets:
        extract_wpa_key_mic(pkt)
        
if __name__ == "__main__":
    main()
