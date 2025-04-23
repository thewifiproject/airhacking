# client.py
import requests
import time

server_ip = "http://100.70.55.182:5000"  # Nahraď IP serveru

# Připojíme se k serveru, abychom informovali o našemu připojení
requests.post(f"{server_ip}/connect")

while True:
    try:
        # Zkontrolujeme nový příkaz na serveru
        response = requests.post(f"{server_ip}/command", data={'cmd': 'whoami'})
        print(f"Výsledek příkazu: {response.text}")
    except Exception as e:
        print(f"Chyba při spojení s serverem: {e}")
    
    time.sleep(10)  # Každých 10 sekund zkontroluje server na nové příkazy
