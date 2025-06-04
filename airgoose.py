import argparse
from scapy.all import ARP, ICMP, UDP, Ether, RadioTap, Dot11, Dot11Deauth, IP, sendp, wrpcap
import signal
import sys

def signal_handler(sig, frame):
    print("\n[!] Přerušeno uživatelem (CTRL+C), ukončuji...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def forge_arp_packet(src_mac, dst_mac, src_ip, dst_ip):
    packet = Ether(src=src_mac, dst=dst_mac) / ARP(psrc=src_ip, pdst=dst_ip)
    return packet

def forge_icmp_packet(src_mac, dst_mac, src_ip, dst_ip):
    packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()
    return packet

def forge_udp_packet(src_mac, dst_mac, src_ip, dst_ip, sport, dport):
    packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    return packet

def forge_deauth_packet(src_mac, dst_mac, ap_mac):
    packet = RadioTap() / Dot11(addr1=dst_mac, addr2=src_mac, addr3=ap_mac) / Dot11Deauth()
    return packet

def main():
    parser = argparse.ArgumentParser(description="AirGoose: Packet forging tool for ARP, ICMP, UDP, and Deauthentication packets")
    parser.add_argument('--arp', action='store_true', help='Forge an ARP packet')
    parser.add_argument('--icmp', action='store_true', help='Forge an ICMP packet')
    parser.add_argument('--udp', action='store_true', help='Forge a UDP packet')
    parser.add_argument('--deauth', action='store_true', help='Forge a Deauthentication packet')
    parser.add_argument('-a', '--apmac', type=str, help='Set Access Point MAC address')
    parser.add_argument('-s', '--srcmac', type=str, required=True, help='Set Source MAC address')
    parser.add_argument('-d', '--dstmac', type=str, required=True, help='Set Destination MAC address')
    parser.add_argument('-t', '--target', type=str, help='Set Destination IP [Port]')
    parser.add_argument('--si', '--srcip', type=str, help='Set Source IP [Port]')
    parser.add_argument('-o', '--output', type=str, help='Write packet to this pcap file')
    parser.add_argument('-c', '--count', type=int, default=1, help='Set number of packets to generate')

    args = parser.parse_args()

    packets = []
    for _ in range(args.count):
        if args.arp:
            if not args.si or not args.target:
                print("Source and target IPs must be specified for ARP packets.")
                return
            src_ip, dst_ip = args.si.split(':')[0], args.target.split(':')[0]
            packets.append(forge_arp_packet(args.srcmac, args.dstmac, src_ip, dst_ip))
        elif args.icmp:
            if not args.si or not args.target:
                print("Source and target IPs must be specified for ICMP packets.")
                return
            src_ip, dst_ip = args.si.split(':')[0], args.target.split(':')[0]
            packets.append(forge_icmp_packet(args.srcmac, args.dstmac, src_ip, dst_ip))
        elif args.udp:
            if not args.si or not args.target:
                print("Source and target IPs and ports must be specified for UDP packets.")
                return
            src_ip, dst_ip = args.si.split(':')[0], args.target.split(':')[0]
            sport, dport = int(args.si.split(':')[1]), int(args.target.split(':')[1])
            packets.append(forge_udp_packet(args.srcmac, args.dstmac, src_ip, dst_ip, sport, dport))
        elif args.deauth:
            if not args.apmac:
                print("Access Point MAC address must be specified for deauthentication packets.")
                return
            packets.append(forge_deauth_packet(args.srcmac, args.dstmac, args.apmac))
        else:
            print("No packet type specified.")
            return

    if args.output:
        wrpcap(args.output, packets)
        print(f"Packets written to {args.output}")
    else:
        for packet in packets:
            sendp(packet)
        print("Packets sent.")

if __name__ == "__main__":
    main()
