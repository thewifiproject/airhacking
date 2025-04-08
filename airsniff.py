import scapy.all as scapy
import curses
import argparse
import threading
import time
import os
import csv
import signal

# Global variables for captured data
networks = []
stations = []
handshake_frames = []  # List to store captured EAPOL frames (handshakes)
capture_name = ''
channel = None
bssid_filter = None
scanning_thread = None
stop_scanning = False  # Flag to control the scanning thread

# Function to handle the network sniffing and scanning
def scan_networks(interface, stdscr):
    global networks, stations, handshake_frames, capture_name, channel, bssid_filter, stop_scanning

    # Check if the interface starts with "wlan"
    if not interface.startswith("wlan"):
        print(f"Wireless card '{interface}' not supported!")
        return

    # Check if the interface is in monitor mode
    mode = os.popen(f"iwconfig {interface}").read()
    if "Mode:Monitor" not in mode:
        print(f"Monitor mode is not enabled on the wireless card '{interface}'!")
        return

    scapy.conf.iface = interface
    scapy.conf.promisc = True

    def packet_handler(pkt):
        global networks, stations, handshake_frames
        if pkt.haslayer(scapy.Dot11Beacon):
            ssid = pkt[scapy.Dot11Elt].info.decode(errors='ignore') if pkt.haslayer(scapy.Dot11Elt) else 'HIDDEN'
            bssid = pkt[scapy.Dot11].addr2
            security = 'WEP' if 'WEP' in pkt.sprintf('%Dot11Beacon.cap%') else 'WPA' if 'WPA' in pkt.sprintf('%Dot11Beacon.cap%') else 'WPA2' if 'WPA2' in pkt.sprintf('%Dot11Beacon.cap%') else 'Unknow...'
            channel = pkt[scapy.Dot11Elt:3].info.decode(errors='ignore') if pkt.haslayer(scapy.Dot11Elt) else 'N/A'
            signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100

            if bssid_filter is None or bssid_filter == bssid:
                networks.append({
                    'SSID': ssid,
                    'BSSID': bssid,
                    'Security': security,
                    'Channel': channel,
                    'Signal': signal,
                    'WPS': 'YES' if 'wps' in pkt.sprintf('%Dot11Beacon.cap%') else 'NO'
                })
                stations = []

            # Dynamic terminal output using curses
            stdscr.clear()
            print_networks(stdscr)
            stdscr.refresh()

        elif pkt.haslayer(scapy.EAPOL):  # Capture EAPOL frames (handshakes)
            print(f"[EAPOL] Captured EAPOL frame from BSSID: {pkt[scapy.Dot11].addr2}")
            handshake_frames.append(pkt)  # Store the EAPOL frame

        elif pkt.haslayer(scapy.Dot11Auth):  # Detect PMKID frames (for WPA attacks)
            auth_pkt = pkt[scapy.Dot11Auth]
            if auth_pkt.algo == 0x01:  # PMKID frame
                print(f"[PMKID] Captured PMKID frame from BSSID: {pkt[scapy.Dot11].addr2}")

    def print_networks(stdscr):
        max_y, max_x = stdscr.getmaxyx()

        # Print networks in a table format
        stdscr.addstr(0, 0, f"Networks (Ctrl+C to exit) - Capturing on: {interface}", curses.A_BOLD)
        stdscr.addstr(2, 0, "SSID          BSSID                Security  Channel Signal  WPS")
        stdscr.addstr(3, 0, "-" * (max_x - 1))

        y_offset = 4
        for net in networks:
            stdscr.addstr(y_offset, 0, f"{net['SSID']: <15} {net['BSSID']: <18} {net['Security']: <8} {net['Channel']: <7} {net['Signal']: <7} {net['WPS']}")
            y_offset += 1

        # Print stations information
        if len(stations) > 0:
            stdscr.addstr(y_offset, 0, "Stations:")
            y_offset += 1
            for station in stations:
                stdscr.addstr(y_offset, 0, f"MAC: {station['MAC']} Channel: {station['Channel']} Signal: {station['Signal']}")
                y_offset += 1

    # Start sniffing, with a condition to stop based on the flag
    while not stop_scanning:
        scapy.sniff(iface=interface, prn=packet_handler, store=0, timeout=1, filter="wlan", count=0)

# Function to save the captured handshakes to a file
def save_handshake_capture(filename):
    global handshake_frames
    if handshake_frames:
        scapy.wrpcap(f"{filename}.cap", handshake_frames)
        print(f"Handshake capture saved as {filename}.cap")
    else:
        print("No handshake captured.")

# Function to save the capture to CSV and .cap file
def save_capture(filename):
    global networks, stations
    # Save the networks information to a CSV file
    with open(f'{filename}.csv', 'w', newline='') as csvfile:
        fieldnames = ['SSID', 'BSSID', 'Security', 'Channel', 'Signal', 'WPS']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for net in networks:
            writer.writerow(net)

    # Save the packet capture as a .cap file
    scapy.wrpcap(f"{filename}.cap", networks)

# Argument parser setup
def parse_arguments():
    parser = argparse.ArgumentParser(description="AirSniff")
    parser.add_argument("interface", help="Interface to scan on")
    parser.add_argument("-c", "--channel", help="Channel to scan", type=int)
    parser.add_argument("-b", "--bssid", help="BSSID to filter", type=str)
    parser.add_argument("-o", "--output", help="Output filename", default="capture")
    return parser.parse_args()

# Function to change the channel
def set_channel(interface, channel):
    if channel:
        os.system(f"iw dev {interface} set channel {channel}")

# Thread to handle network scanning
def start_scanning(stdscr):
    global capture_name, channel, bssid_filter, stop_scanning
    args = parse_arguments()

    capture_name = args.output
    channel = args.channel
    bssid_filter = args.bssid

    try:
        set_channel(args.interface, channel)
    except Exception as e:
        print(f"Error setting channel: {e}")
        return

    try:
        scan_networks(args.interface, stdscr)
    except KeyboardInterrupt:
        stop_scanning = True
        save_capture(capture_name)
        save_handshake_capture(capture_name)  # Save handshakes as well
        print("\nCapture saved. Exiting...")

def main():
    global stop_scanning
    stop_scanning = False  # Reset the stop flag at the start of the program

    def handler(signum, frame):
        global stop_scanning
        stop_scanning = True

    signal.signal(signal.SIGINT, handler)  # Catch Ctrl+C

    curses.wrapper(start_scanning)

# Run the tool
if __name__ == "__main__":
    main()
