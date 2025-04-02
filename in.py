from scapy.all import *
import re

def extract_handshake_info(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)
    
    # Variables to store relevant information
    ap_mac = None
    sta_mac = None
    ssid = None
    bssid = None
    anonce = None
    snonce = None
    key_mic = None

    # Iterate through packets to find handshake packets
    for packet in packets:
        # Check if packet is a beacon or probe request (for SSID and BSSID)
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Beacon].info.decode(errors='ignore')  # SSID
            bssid = packet[Dot11].addr3  # BSSID (AP MAC)
        elif packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11ProbeResp].info.decode(errors='ignore')  # SSID
            bssid = packet[Dot11].addr3  # BSSID (AP MAC)
        
        # Check if packet is part of the 4-way handshake
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 13:
            # Message 1 (from AP to STA), looking for ANonce
            if packet.haslayer(EAPOL):
                if packet[Dot11].addr1 == bssid:  # Check if it's from the AP
                    # Extract ANonce from EAPOL Message 1
                    eapol = packet[EAPOL]
                    anonce = eapol.payload.load[:32]  # ANonce is first 32 bytes

            # Message 2 (from STA to AP), looking for SNonce and Key MIC
            if packet.haslayer(EAPOL):
                if packet[Dot11].addr1 == sta_mac:  # Check if it's from the STA
                    # Extract Key MIC and SNonce from EAPOL Message 2
                    eapol = packet[EAPOL]
                    key_mic = eapol.payload.load[16:32]  # Key MIC is 16-31 bytes
                    snonce = eapol.payload.load[32:64]  # SNonce is next 32 bytes

                    # Save STA MAC address
                    sta_mac = packet[Dot11].addr2

    # Return all extracted information
    return {
        'AP MAC': bssid,
        'STA MAC': sta_mac,
        'SSID': ssid,
        'BSSID': bssid,
        'ANonce': anonce,
        'SNonce': snonce,
        'Key MIC': key_mic
    }

# Example usage
pcap_file = 'Shak.pcap'
info = extract_handshake_info(pcap_file)
print(info)
