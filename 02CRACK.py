from scapy.all import rdpcap, EAPOL

def extract_wpa_key_mic_from_message_2(packets):
    message_count = 0
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            eapol = pkt[EAPOL]
            if eapol.type == 3:  # EAPOL-Key (Message 2, 3, or 4)
                message_count += 1
                # Check if it's the second message in the handshake (Message 2)
                if message_count == 2:
                    key_mic = eapol.key_mic
                    print(f"WPA Key MIC from Message 2: {key_mic.hex()}")
                    break  # We only want to extract from Message 2

def main():
    pcap_file = "SHAK.cap"
    packets = rdpcap(pcap_file)
    extract_wpa_key_mic_from_message_2(packets)

if __name__ == "__main__":
    main()
