import argparse
from scapy.all import *

def extract_key_info(packet):
    # Ensure the packet is an 802.11 frame with EAPOL
    if packet.haslayer(EAPOL):
        eapol_layer = packet.getlayer(EAPOL)
        if eapol_layer.type == 3:  # EAPOL Key frame (Message 2 or 3)
            # Extract the frame type (Message 2 or Message 3)
            if eapol_layer.key_info == 0x02:  # Message 2 (AP -> STA)
                anonce = eapol_layer.key_nonce
                s_nonce = None  # Not applicable for Message 2
                key_mic = eapol_layer.key_mic
                message_type = "Message 2"
            elif eapol_layer.key_info == 0x01:  # Message 3 (STA -> AP)
                s_nonce = eapol_layer.key_nonce
                anonce = None  # Not applicable for Message 3
                key_mic = eapol_layer.key_mic
                message_type = "Message 3"
            else:
                return None

            # Extract SSID, BSSID, AP MAC, and STA MAC
            ssid = packet.info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else "N/A"
            bssid = packet.addr3 if packet.haslayer(Dot11) else None
            ap_mac = packet.addr2 if packet.haslayer(Dot11) else None
            sta_mac = packet.addr1 if packet.haslayer(Dot11) else None

            return {
                "Message Type": message_type,
                "Key MIC": key_mic.hex() if key_mic else None,
                "ANonce": anonce.hex() if anonce else None,
                "SNonce": s_nonce.hex() if s_nonce else None,
                "SSID": ssid,
                "BSSID": bssid,
                "AP MAC": ap_mac,
                "STA MAC": sta_mac
            }
    return None

def process_pcap(file_path):
    packets = rdpcap(file_path)
    results = []
    
    for packet in packets:
        key_info = extract_key_info(packet)
        if key_info:
            results.append(key_info)
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Extract key information from a .pcap or .cap file.")
    parser.add_argument('file', help="Path to the .pcap or .cap file")
    args = parser.parse_args()

    results = process_pcap(args.file)
    if results:
        for result in results:
            print("Message Type:", result["Message Type"])
            print("Key MIC:", result["Key MIC"])
            print("ANonce:", result["ANonce"])
            print("SNonce:", result["SNonce"])
            print("SSID:", result["SSID"])
            print("BSSID:", result["BSSID"])
            print("AP MAC:", result["AP MAC"])
            print("STA MAC:", result["STA MAC"])
            print("-" * 50)
    else:
        print("No valid key information found in the capture.")

if __name__ == "__main__":
    main()
