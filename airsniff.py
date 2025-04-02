import sys
import asyncio
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTextEdit, QWidget, QPushButton, QTreeWidget, QTreeWidgetItem, QSplitter
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt
from scapy.all import sniff
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options
import threading

class PacketSniffer:
    def __init__(self, packet_callback):
        self.packet_callback = packet_callback

    def start_sniffing(self):
        sniff(prn=self.packet_callback, store=True)

class MitmProxy:
    def __init__(self):
        self.opts = options.Options(listen_host='0.0.0.0', listen_port=8080)
        self.loop = asyncio.new_event_loop()
        self.m = DumpMaster(self.opts, with_termlog=False, with_dumper=False)
        self.m.event_loop = self.loop

    def start_proxy(self):
        asyncio.set_event_loop(self.loop)
        self.m.run()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.sniffer = PacketSniffer(self.packet_callback)
        self.mitm = MitmProxy()

    def init_ui(self):
        self.setWindowTitle('Advanced MITM Tool')
        self.setGeometry(300, 300, 1200, 800)
        self.setWindowIcon(QIcon('icon.png'))

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        self.layout = QVBoxLayout(self.main_widget)

        splitter = QSplitter(Qt.Vertical)

        self.packet_list = QTreeWidget()
        self.packet_list.setHeaderLabels(['No.', 'Summary'])
        self.packet_list.itemClicked.connect(self.display_packet_details)
        splitter.addWidget(self.packet_list)

        self.packet_details = QTextEdit()
        splitter.addWidget(self.packet_details)

        self.layout.addWidget(splitter)

        self.start_sniffing_btn = QPushButton('Start Sniffing', self)
        self.start_sniffing_btn.clicked.connect(self.start_sniffing)
        self.layout.addWidget(self.start_sniffing_btn)

        self.start_mitm_btn = QPushButton('Start MITM Proxy', self)
        self.start_mitm_btn.clicked.connect(self.start_mitm_proxy)
        self.layout.addWidget(self.start_mitm_btn)

    def packet_callback(self, packet):
        packet_summary = packet.summary()
        packet_item = QTreeWidgetItem([str(len(self.packet_list)), packet_summary])
        packet_item.setData(0, Qt.UserRole, packet)
        self.packet_list.addTopLevelItem(packet_item)

    def display_packet_details(self, item):
        packet = item.data(0, Qt.UserRole)
        self.packet_details.setText(packet.show(dump=True))

    def start_sniffing(self):
        threading.Thread(target=self.sniffer.start_sniffing).start()

    def start_mitm_proxy(self):
        threading.Thread(target=self.mitm.start_proxy).start()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_win = MainWindow()
    main_win.show()
    sys.exit(app.exec())
