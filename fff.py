import pyshark
import argparse
from collections import defaultdict


def capture_wifi(interface):
    # Create a capture object using PyShark to listen on the specified interface
    capture = pyshark.LiveCapture(interface=interface, display_filter='wlan.fc.type_subtype == 0x08')

    networks = defaultdict(list)
    clients = defaultdict(list)

    # Parse the packets and extract relevant details
    for packet in capture.sniff_continuously():
        if 'wlan' in packet:
            if hasattr(packet.wlan, 'addr2') and hasattr(packet.wlan, 'ssid'):
                bssid = packet.wlan.addr2
                ssid = packet.wlan.ssid
                encryption = 'OPN'  # Default is no encryption
                auth = 'OPN'  # Default is open authentication
                channel = packet.wlan_radio.channel

                # Check for encryption and authentication
                if 'wlan.sa' in packet:
                    auth = 'PSK'  # PSK is default for WPA/WPA2
                    if 'CCMP' in packet:
                        encryption = 'WPA2'
                    elif 'TKIP' in packet:
                        encryption = 'WPA'
                    elif 'WEP' in packet:
                        encryption = 'WEP'

                # Handle Opportunistic Wireless Encryption (OWE)
                if 'OWE' in packet:
                    encryption = 'OWE'

                power = packet.dbm_antenna_signal if hasattr(packet, 'dbm_antenna_signal') else None
                clients[bssid].append(packet.wlan.sa)  # Track associated clients or searching stations
                networks[bssid].append({
                    'SSID': ssid,
                    'BSSID': bssid,
                    'Encryption': encryption,
                    'Auth': auth,
                    'Channel': channel,
                    'PWR': power
                })

    return networks, clients


def print_network_info(networks, clients):
    print("{:<20} {:<20} {:<10} {:<10} {:<10} {:<20}".format('SSID', 'BSSID', 'Encryption', 'Auth', 'Channel', 'Power'))
    print("-" * 90)

    for bssid, network_info in networks.items():
        for net in network_info:
            ssid = net['SSID']
            bssid = net['BSSID']
            encryption = net['Encryption']
            auth = net['Auth']
            channel = net['Channel']
            power = net['PWR'] if net['PWR'] else "N/A"

            # Output network details
            print("{:<20} {:<20} {:<10} {:<10} {:<10} {:<20}".format(ssid, bssid, encryption, auth, channel, power))

            # Output associated stations (clients)
            stations = clients[bssid]
            if stations:
                for station in stations:
                    print(f"  Client MAC: {station}")
            else:
                print(f"  Client MAC: (not associated)")


def main():
    parser = argparse.ArgumentParser(description='Capture and display nearby Wi-Fi networks')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to capture from')
    args = parser.parse_args()

    print("Capturing nearby Wi-Fi networks...")
    networks, clients = capture_wifi(args.interface)

    print_network_info(networks, clients)


if __name__ == '__main__':
    main()
