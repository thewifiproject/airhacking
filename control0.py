import sys
import os
import random
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QListWidget, QTextEdit, QFileDialog, QTabWidget
)
from PySide6.QtCore import Qt, QTimer


class RemoteFileBrowser(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        self.path_input = QLineEdit("C:/users/hacked/documents")
        self.search_btn = QPushButton("Search")
        self.file_list = QListWidget()
        self.delete_btn = QPushButton("Delete Selected")

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.search_btn)

        self.layout.addLayout(path_layout)
        self.layout.addWidget(self.file_list)
        self.layout.addWidget(self.delete_btn)

        self.filesystem = {
            "C:/users/hacked/documents": ["passwords.txt", "hack_plan.pdf", "diary.docx"],
            "C:/users/hacked/desktop": ["backdoor.py", "todo.txt", "crypto_keys.txt"],
            "C:/windows/temp": ["malware_stub.exe", "trace_logs.tmp"]
        }

        self.search_btn.clicked.connect(self.search_files)
        self.delete_btn.clicked.connect(self.delete_file)

    def search_files(self):
        path = self.path_input.text()
        self.file_list.clear()
        if path in self.filesystem:
            for f in self.filesystem[path]:
                self.file_list.addItem(f)

    def delete_file(self):
        selected = self.file_list.currentItem()
        if selected:
            path = self.path_input.text()
            filename = selected.text()
            if filename in self.filesystem.get(path, []):
                self.filesystem[path].remove(filename)
            self.search_files()


class MalwareUploadTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        self.path_label = QLabel("Upload to Path:")
        self.path_input = QLineEdit("C:/windows/temp")

        self.upload_btn = QPushButton("Upload Malware")
        self.upload_crypto_btn = QPushButton("Upload Cryptojacker")

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.layout.addWidget(self.path_label)
        self.layout.addWidget(self.path_input)
        self.layout.addWidget(self.upload_btn)
        self.layout.addWidget(self.upload_crypto_btn)
        self.layout.addWidget(self.output)

        self.upload_btn.clicked.connect(self.upload_generic)
        self.upload_crypto_btn.clicked.connect(self.upload_cryptojacker)

    def upload_generic(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Malware File")
        if file_path:
            dest = self.path_input.text()
            filename = os.path.basename(file_path)
            self.output.append(f"[+] Uploading {filename} to {dest}...")
            QTimer.singleShot(1500, lambda: self.output.append(f"[+] {filename} dropped at {dest}"))
            QTimer.singleShot(2500, lambda: self.output.append("[i] Execution triggered.\n"))

    def upload_cryptojacker(self):
        dest = self.path_input.text()
        filename = "monero_miner.exe"

        self.output.append(f"[+] Uploading {filename} to {dest}...")
        QTimer.singleShot(1200, lambda: self.output.append("[+] File deployed."))
        QTimer.singleShot(2000, lambda: self.output.append("[+] Connecting to mining pool..."))
        QTimer.singleShot(2800, lambda: self.output.append("[+] CPU usage spiked."))
        QTimer.singleShot(3500, lambda: self.output.append("[✓] Cryptojacker active.\n"))


class CommandShell(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.input = QLineEdit()
        self.send_btn = QPushButton("Execute")

        self.layout.addWidget(self.output)
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.input)
        input_layout.addWidget(self.send_btn)
        self.layout.addLayout(input_layout)

        self.send_btn.clicked.connect(self.execute_command)

    def execute_command(self):
        cmd = self.input.text()
        self.output.append(f"C:\\> {cmd}")
        responses = [
            "Access granted.",
            "Directory listed.",
            "Service stopped.",
            "Process killed.",
            "File deleted.",
            "Remote shutdown initiated.",
            "Privileges escalated.",
            "Reverse shell established."
        ]
        self.output.append(random.choice(responses))
        self.input.clear()


class CalculatorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        self.expr_input = QLineEdit()
        self.calc_btn = QPushButton("Calculate")
        self.result_display = QLabel("")

        self.layout.addWidget(self.expr_input)
        self.layout.addWidget(self.calc_btn)
        self.layout.addWidget(self.result_display)

        self.calc_btn.clicked.connect(self.calculate)

    def calculate(self):
        expr = self.expr_input.text()
        try:
            result = eval(expr, {"__builtins__": {}})
            self.result_display.setText(str(result))
        except:
            self.result_display.setText("Error")


class RemoteControlApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Access Control Panel")
        self.setGeometry(200, 150, 800, 600)

        self.tabs = QTabWidget()
        self.tabs.addTab(RemoteFileBrowser(), "File Browser")
        self.tabs.addTab(MalwareUploadTab(), "Upload")
        self.tabs.addTab(CommandShell(), "Shell")
        self.tabs.addTab(CalculatorTab(), "Calc")

        self.setCentralWidget(self.tabs)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RemoteControlApp()
    window.show()
    sys.exit(app.exec())
