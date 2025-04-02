def extract_handshake_info(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

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
            # Print out EAPOL packets to check for presence of WPA handshake
            if pkt.haslayer(EAPOL):
                print(pkt.summary())  # Print summary of the packet for debugging

            # Extract SSID and BSSID
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame (SSID and BSSID)
                ssid = pkt.info.decode(errors='ignore')  # Extract SSID
                bssid = pkt.addr3  # BSSID is the AP MAC address
            # Extract AP MAC (BSSID)
            if pkt.haslayer(EAPOL):
                # Check for Message 2 (EAPOL) - Client sends this to the AP
                if pkt[Dot11].addr1 == bssid:  # The destination is the AP
                    if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0x04:  # EAPOL frame
                        # Message 2 (STA -> AP) contains SNonce and MIC
                        message2 = pkt
                        sta_mac = pkt.addr2  # Client MAC address (STA)
                        snonce = pkt[Raw].load[0:32]  # SNonce (first 32 bytes)
                        key_mic = pkt[Raw].load[32:48]  # Key MIC (next 16 bytes)
                # Check for Message 3 (EAPOL) - AP sends this to the client
                if pkt[Dot11].addr2 == bssid:  # The source is the AP
                    if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 0x04:  # EAPOL frame
                        # Message 3 (AP -> STA) contains ANonce
                        message3 = pkt
                        anonce = pkt[Raw].load[0:32]  # ANonce (first 32 bytes)

    # Output the collected information
    if message2 and message3:
        print("SSID:", ssid)
        print("BSSID (AP MAC):", bssid)
        print("AP MAC:", ap_mac)
        print("STA MAC (Client MAC):", sta_mac)
        print("SNonce (from Message 2):", snonce.hex())
        print("ANonce (from Message 3):", anonce.hex())
        print("Key MIC (from Message 2):", key_mic.hex())
    else:
        print("Could not extract the required information from the handshake.")
