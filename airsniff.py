import sys
import threading
import time
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit
from scapy.all import sniff, ARP, send, DNS, IP, TCP, Raw
from sslstrip import SSLStrip  # Assuming you have this tool installed

class MITMTool(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("MITM Sniffer Tool")
        self.setGeometry(100, 100, 800, 600)

        self.layout = QVBoxLayout(self)

        self.start_button = QPushButton("Start Sniffing", self)
        self.start_button.clicked.connect(self.start_sniffing)

        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)

        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.log_area)

        self.setLayout(self.layout)

    def start_sniffing(self):
        self.log_area.append("Starting to sniff all traffic...")
        # Start sniffing in a separate thread
        threading.Thread(target=self.sniff_packets).start()

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0)

    def process_packet(self, packet):
        if packet.haslayer(TCP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(Raw):
                data = packet[Raw].load
                if b"HTTP" in data:
                    self.log_area.append(f"HTTP Packet from {ip_src} -> {ip_dst}:\n{data.decode('utf-8', errors='ignore')}")
                elif b"POST" in data:
                    self.log_area.append(f"POST request from {ip_src} -> {ip_dst}:\n{data.decode('utf-8', errors='ignore')}")
            
            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
                if packet.haslayer(TLS):
                    self.log_area.append(f"TLS/SSL traffic captured from {ip_src} -> {ip_dst}")
                    self.handle_ssl_decryption(packet)

    def handle_ssl_decryption(self, packet):
        # Decrypt the SSL/TLS traffic (this is where you would need SSLStrip or your own method)
        try:
            decrypted_data = SSLStrip.decrypt(packet)
            self.log_area.append(f"Decrypted HTTPS Data: {decrypted_data}")
        except Exception as e:
            self.log_area.append(f"Error in SSL decryption: {e}")

def main():
    app = QApplication(sys.argv)
    window = MITMTool()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
