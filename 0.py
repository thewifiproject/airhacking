from scapy.all import rdpcap, EAPOL

def extract_wpa_key_mic(packet):
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key
            key_mic = eapol.key_mic
            print(f"WPA Key MIC: {key_mic.hex()}")

def main():
    pcap_file = "wpa.cap"
    packets = rdpcap(pcap_file)
    for pkt in packets:
        extract_wpa_key_mic(pkt)
        
if __name__ == "__main__":
    main()
