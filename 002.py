from scapy.all import rdpcap, EAPOL

# Read in the pcap file containing the WPA2 handshake
packets = rdpcap("Shak.cap")

# Loop through packets and look for EAPOL frames (which contain the handshake)
for pkt in packets:
    if pkt.haslayer(EAPOL):
        # Display the raw bytes in the EAPOL layer (this is where the encrypted PSK info is)
        print(f"Encrypted Data (Hex): {pkt[EAPOL].payload.raw_packet().hex()}")
