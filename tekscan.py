import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QTextEdit, QPushButton, QLineEdit
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QFont
from scapy.all import sniff, IP, TCP, UDP, ARP
import socket
class PaketYakalayici(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TekScan")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #f0f0f0;")        
        font = QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        self.layout = QVBoxLayout()
        self.info_label = QLabel("Yeni gelen paketler burada gösterilecek:")
        self.info_label.setFont(font)
        
        self.paket_text = QTextEdit()
        self.paket_text.setFont(font)
        self.paket_text.setReadOnly(True)
        self.paket_text.setStyleSheet("background-color: #ffffff; color: #000000; border: 1px solid #cccccc;")
        
        self.port_scan_label = QLabel("Port Tarama:")
        self.port_scan_label.setFont(font)
        
        self.target_input = QLineEdit()
        self.target_input.setFont(font)
        self.target_input.setPlaceholderText("Hedef IP adresini girin")
        self.target_input.setStyleSheet("background-color: #ffffff; color: #000000; border: 1px solid #cccccc;")

        self.scan_button = QPushButton("Tara")
        self.scan_button.setFont(font)
        self.scan_button.setStyleSheet("background-color: #4caf50; color: #ffffff; padding: 5px; border: none;")
        self.scan_button.clicked.connect(self.port_tarama)

        self.layout.addWidget(self.info_label)
        self.layout.addWidget(self.paket_text)
        self.layout.addWidget(self.port_scan_label)
        self.layout.addWidget(self.target_input)
        self.layout.addWidget(self.scan_button)
        
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        self.timer = QTimer()
        self.timer.timeout.connect(self.guncelle_paketler)
        self.timer.start(5000)
        self.paket_listesi = []

    def guncelle_paketler(self):
        self.paket_text.clear()
        sniff(count=5, prn=self.paket_ekle, filter="ip", timeout=5)

    def paket_ekle(self, paket):
        paket_bilgisi = self.paket_bilgisi_al(paket)
        self.paket_text.append(paket_bilgisi)
        self.paket_text.append("=" * 50)

    def paket_bilgisi_al(self, paket):
        bilgi = ""
        if IP in paket:
            bilgi += f"Kaynak IP: {paket[IP].src}\n"
            bilgi += f"Varış IPsi: {paket[IP].dst}\n"
        if TCP in paket:
            bilgi += f"Kaynak Portu: {paket[TCP].sport}\n"
            bilgi += f"Varış Portu: {paket[TCP].dport}\n"
            bilgi += "Protokol: TCP\n"
        elif UDP in paket:
            bilgi += f"Kaynak Portu: {paket[UDP].sport}\n"
            bilgi += f"Varış Portu: {paket[UDP].dport}\n"
            bilgi += "Protokol: UDP\n"
        elif ARP in paket:
            bilgi += f"ARP Tipi: {paket[ARP].op}\n"
            bilgi += f"Kaynak MACi: {paket[ARP].hwsrc}\n"
            bilgi += f"Varış MACi: {paket[ARP].hwdst}\n"
        return bilgi

    def port_tarama(self):
        target_ip = self.target_input.text()
        self.paket_text.append(f"Port taraması başlatılıyor: {target_ip}")
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                self.paket_text.append(f"Port {port}: Açık")
            sock.close()
        self.paket_text.append("Port taraması tamamlandı.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PaketYakalayici()
    window.show()
    sys.exit(app.exec_())
