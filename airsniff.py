import scapy.all as scapy
import curses
import argparse
import threading
import time
import os
import csv
import signal

networks = []
handshake_frames = []
capture_name = ''
channel = None
bssid_filter = None
stop_scanning = False
current_hopping_channel = None

def channel_hopper(interface):
    global stop_scanning, current_hopping_channel
    channel_list = [1, 6, 11]  # You can expand this
    index = 0
    while not stop_scanning:
        current_hopping_channel = channel_list[index]
        os.system(f"iw dev {interface} set channel {current_hopping_channel}")
        index = (index + 1) % len(channel_list)
        time.sleep(0.5)

def extract_channel(pkt):
    elt = pkt.getlayer(scapy.Dot11Elt)
    while elt:
        if elt.ID == 3:
            return ord(elt.info)
        elt = elt.payload.getlayer(scapy.Dot11Elt)
    return 'N/A'

def detect_security(pkt):
    capabilities = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").lower()
    if 'privacy' in capabilities:
        if pkt.haslayer(scapy.Dot11EltRSN):
            return 'WPA2'
        else:
            return 'WEP/WPA'
    return 'Open'

def packet_handler(pkt, stdscr, interface):
    global networks, handshake_frames

    if pkt.haslayer(scapy.Dot11Beacon):
        ssid = pkt[scapy.Dot11Elt].info.decode(errors='ignore') if pkt.haslayer(scapy.Dot11Elt) else 'HIDDEN'
        bssid = pkt[scapy.Dot11].addr2
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        security = detect_security(pkt)
        channel = extract_channel(pkt)
        wps = 'YES' if 'wps' in pkt.sprintf('%Dot11Beacon.cap%').lower() else 'NO'

        if bssid_filter is None or bssid_filter == bssid:
            if not any(net['BSSID'] == bssid for net in networks):
                networks.append({
                    'SSID': ssid,
                    'BSSID': bssid,
                    'Security': security,
                    'Channel': channel,
                    'Signal': signal,
                    'WPS': wps
                })
                print_networks(stdscr, interface)

    elif pkt.haslayer(scapy.EAPOL):
        bssid = pkt[scapy.Dot11].addr2
        print(f"[EAPOL] Captured from {bssid}")
        handshake_frames.append(pkt)

    elif pkt.haslayer(scapy.Dot11Auth):
        if pkt[scapy.Dot11Auth].algo == 0x01:
            print(f"[PMKID] Detected from {pkt[scapy.Dot11].addr2}")

def print_networks(stdscr, interface):
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()

    if current_hopping_channel is not None:
        stdscr.addstr(0, 0, f"[ CH ({current_hopping_channel}) ]", curses.A_BOLD)

    stdscr.addstr(2, 0, f"Networks (Ctrl+C to exit) - Interface: {interface}", curses.A_BOLD)
    stdscr.addstr(4, 0, "SSID          BSSID                Security    Channel Signal  WPS")
    stdscr.addstr(5, 0, "-" * (max_x - 1))

    for i, net in enumerate(networks):
        if 6 + i >= max_y - 1:
            break
        stdscr.addstr(6 + i, 0, f"{net['SSID']: <15} {net['BSSID']: <18} {net['Security']: <10} {net['Channel']: <7} {net['Signal']: <7} {net['WPS']}")

    stdscr.refresh()

def scan_networks(interface, stdscr):
    global stop_scanning

    if not interface.startswith("wlan"):
        print(f"Interface '{interface}' not supported.")
        return

    mode = os.popen(f"iwconfig {interface}").read()
    if "Mode:Monitor" not in mode:
        print(f"Interface '{interface}' is not in monitor mode.")
        return

    scapy.conf.iface = interface
    scapy.conf.promisc = True

    threading.Thread(target=channel_hopper, args=(interface,), daemon=True).start()

    while not stop_scanning:
        scapy.sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, stdscr, interface), store=0, timeout=1)

def save_handshake_capture(filename):
    if handshake_frames:
        scapy.wrpcap(f"{filename}_handshake.cap", handshake_frames)
        print(f"Handshake capture saved to {filename}_handshake.cap")
    else:
        print("No handshake frames captured.")

def save_networks_csv(filename):
    with open(f'{filename}.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['SSID', 'BSSID', 'Security', 'Channel', 'Signal', 'WPS'])
        writer.writeheader()
        for net in networks:
            writer.writerow(net)
    print(f"Network list saved to {filename}.csv")

def parse_arguments():
    parser = argparse.ArgumentParser(description="AirSniff - Wireless Network Scanner & Handshake Capturer")
    parser.add_argument("interface", help="Wireless interface in monitor mode")
    parser.add_argument("-c", "--channel", type=int, help="Set scanning channel")
    parser.add_argument("-b", "--bssid", help="Filter by BSSID")
    parser.add_argument("-o", "--output", default="capture", help="Output filename prefix")
    return parser.parse_args()

def set_channel(interface, ch):
    if ch:
        os.system(f"iw dev {interface} set channel {ch}")

def start_scanning(stdscr):
    global capture_name, channel, bssid_filter, stop_scanning
    args = parse_arguments()

    capture_name = args.output
    channel = args.channel
    bssid_filter = args.bssid

    try:
        set_channel(args.interface, channel)
        scan_networks(args.interface, stdscr)
    except KeyboardInterrupt:
        stop_scanning = True
        save_networks_csv(capture_name)
        save_handshake_capture(capture_name)
        print("\nCapture complete. Exiting...")

def main():
    global stop_scanning
    stop_scanning = False

    def handler(signum, frame):
        global stop_scanning
        stop_scanning = True

    signal.signal(signal.SIGINT, handler)
    curses.wrapper(start_scanning)

if __name__ == "__main__":
    main()
