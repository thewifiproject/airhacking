import binascii
import hmac
import hashlib
from struct import pack

# Hardcoded inputs
ssid = "test"
passphrase = "biscotte"
ap_mac = "00:0D:93:EB:B0:8C"
client_mac = "00:09:5B:91:53:5D"
anonce = "54adc644966dc8423d44364a1de9ec22415522bd0555ee718f8a53b8d679470c"
snonce = "fe5f0c5b5423815f35fe606720bbb9466d8601a8b4493af4cf5a0317f38c8387"
mic_to_test = "28a8c895b717e57227b6a7eee3e53445"
eapol_hex = (
    "01030077FE010900200000000000000000FE5F0C5B5423815F35FE606720BBB946"
    "6D8601A8B4493AF4CF5A0317F38C83870000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000018"
    "DD160050F20101000050F20201000050F20201000050F202"
)

# WPA uses PBKDF2-HMAC-SHA1 for PMK, but the MIC is HMAC-MD5 for WPA/TKIP
def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)//160):
        hmacsha1 = hmac.new(key, A + b'\x00' + B + pack('B', i), hashlib.sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[:blen]

def parse_mac(mac_str):
    return binascii.unhexlify(mac_str.replace(":", ""))

def main():
    # 1. PMK derivation
    pmk = hashlib.pbkdf2_hmac(
        'sha1',
        passphrase.encode(),
        ssid.encode(),
        4096,
        32
    )

    # 2. PTK derivation (Pairwise Transient Key)
    A = b"Pairwise key expansion"
    B = min(parse_mac(ap_mac), parse_mac(client_mac)) + max(parse_mac(ap_mac), parse_mac(client_mac)) + \
        min(binascii.unhexlify(anonce), binascii.unhexlify(snonce)) + \
        max(binascii.unhexlify(anonce), binascii.unhexlify(snonce))
    ptk = customPRF512(pmk, A, B)

    # 3. EAPOL message (mic field set to 0)
    eapol = bytearray(binascii.unhexlify(eapol_hex))
    # MIC is at byte offset 81 (zero-based) and is 16 bytes long for WPA/TKIP
    eapol[81:81+16] = b"\x00" * 16

    # 4. Calculate MIC using HMAC-MD5 (WPA/TKIP)
    mic = hmac.new(ptk[0:16], bytes(eapol), hashlib.md5).hexdigest()[:32]

    print("Calculated MIC:", mic[:32])
    print("Expected  MIC:", mic_to_test)
    if mic[:32] == mic_to_test.lower():
        print("[+] Passphrase is CORRECT for WPA (TKIP).")
    else:
        print("[-] Passphrase is WRONG for WPA (TKIP).")

if __name__ == "__main__":
    main()
