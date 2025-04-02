from scapy.all import *

def set_promiscuous_mode(interface):
    try:
        conf.iface = interface
        conf.sniff_promisc = True
        print(f"Promiscuous mode enabled on {interface}")
    except Exception as e:
        print(f"Error enabling promiscuous mode: {e}")
