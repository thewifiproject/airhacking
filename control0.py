import time
import random
import sys
from colorama import init, Fore, Style

init(autoreset=True)

def slow_type(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(message, cycles=3):
    for _ in range(cycles):
        for dots in ['.', '..', '...']:
            sys.stdout.write(f'\r{message}{dots} ')
            sys.stdout.flush()
            time.sleep(0.3)
    print()

def fake_calc():
    ops = ['Encrypting payload', 'Injecting NULL bytes', 'Allocating buffer', 'Evading firewall', 'Sniffing handshake']
    for _ in range(10):
        op = random.choice(ops)
        percent = random.randint(5, 99)
        slow_type(f"{Fore.YELLOW}[+] {op}... {percent}% complete", delay=0.01)
        time.sleep(0.2)
    slow_type(f"{Fore.GREEN}[✔] Calculations complete. Exploit vector established.", delay=0.03)

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
  ____       _     _            _   _      _   
 |  _ \ ___ | |__ (_) ___ _ __ | |_(_) ___| |_ 
 | |_) / _ \| '_ \| |/ _ \ '_ \| __| |/ __| __|
 |  _ < (_) | |_) | |  __/ | | | |_| | (__| |_ 
 |_| \_\___/|_.__/|_|\___|_| |_|\__|_|\___|\__|
         Remote Control Takeover Module
""")

def menu():
    print(Fore.CYAN + "\nOptions:")
    print(" [1] Kill Botnet")
    print(" [2] Kill All Bots")
    print(" [3] Re-Control Botnet")
    print(" [4] Exit")

def kill_botnet():
    slow_type(Fore.RED + "[!] Sending self-destruct signal to botnet master node...")
    loading_animation("Uploading exploit")
    fake_calc()
    slow_type(Fore.GREEN + "[✔] Botnet master node offline. Connection terminated.")

def kill_bots():
    slow_type(Fore.RED + "[!] Wiping bots memory and deleting persistence modules...")
    loading_animation("Neutralizing agents")
    fake_calc()
    slow_type(Fore.GREEN + "[✔] All bots destroyed. No callback signals detected.")

def recontrol():
    slow_type(Fore.YELLOW + "[~] Initiating reverse shell on master node...")
    loading_animation("Bypassing firewall")
    fake_calc()
    slow_type(Fore.GREEN + "[✔] Root shell access gained. You now control the botnet.")

def main():
    banner()
    while True:
        menu()
        choice = input(Fore.MAGENTA + "\n[>] Choose an action: ")

        if choice == '1':
            kill_botnet()
        elif choice == '2':
            kill_bots()
        elif choice == '3':
            recontrol()
        elif choice == '4':
            slow_type(Fore.CYAN + "[*] Exiting and clearing session traces...")
            break
        else:
            print(Fore.RED + "Invalid choice. Try again.")

        time.sleep(2)

if __name__ == "__main__":
    main()
