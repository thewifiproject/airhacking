import time
import random
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def slowprint(text, delay=0.05):
    for c in text:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def animation(text, repeat=3, delay=0.2):
    for _ in range(repeat):
        for dots in ['.', '..', '...']:
            sys.stdout.write(f'\r{text}{dots}   ')
            sys.stdout.flush()
            time.sleep(delay)
    print()

def fake_calc():
    slowprint(f"{Fore.CYAN}[+] Calculating shellcode bypass offsets...")
    for i in range(1, 101, random.randint(5, 15)):
        sys.stdout.write(f"\r{Fore.YELLOW}[*] Progress: {i}%")
        sys.stdout.flush()
        time.sleep(0.1)
    print(f"\n{Fore.GREEN}[+] Offset calculation complete.")

def fake_upload():
    animation(f"{Fore.YELLOW}[*] Uploading FantomCryptX.exe")
    slowprint(f"{Fore.GREEN}[+] Upload complete.")
    time.sleep(1)

def fake_shutdown():
    animation(f"{Fore.RED}[!] Sending shutdown command")
    slowprint(f"{Fore.RED}[-] Remote machine will shutdown in 30 seconds...")
    time.sleep(1)

def fake_delete():
    animation(f"{Fore.MAGENTA}[!] Deleting files")
    slowprint(f"{Fore.GREEN}[+] Target filesystem wiped.")
    time.sleep(1)

def backdoor_menu():
    slowprint(f"{Fore.CYAN}[+] Connected to remote machine: 192.168.0.103")
    fake_calc()
    while True:
        print(f"""
{Fore.BLUE}[REMOTE CONTROL MENU]
{Fore.YELLOW}1. Shutdown Target PC
2. Upload FantomCryptX.exe
3. Delete All Files
4. Exit
""")
        choice = input(f"{Fore.CYAN}[>] Enter choice: ")
        if choice == '1':
            fake_shutdown()
        elif choice == '2':
            fake_upload()
        elif choice == '3':
            fake_delete()
        elif choice == '4':
            slowprint(f"{Fore.CYAN}[~] Disconnecting...")
            break
        else:
            print(f"{Fore.RED}[!] Invalid option.")

def twist():
    animation(f"{Fore.RED}[!] Unexpected behavior detected")
    slowprint(f"{Fore.RED}[X] Reverse shell detected...")
    slowprint(f"{Fore.YELLOW}[?] Connection overridden by unknown host: 10.0.0.66")
    animation(f"{Fore.MAGENTA}[!] Uploading payload to YOUR machine")
    slowprint(f"{Fore.RED}[-] Deleting your files...")
    animation(f"{Fore.YELLOW}[!] Retaliation in progress")
    slowprint(f"{Fore.GREEN}[+] You have been hacked back. Logging off...\n")
    time.sleep(2)
    slowprint(f"{Fore.WHITE}[SYSTEM] Shutting down...")
    time.sleep(2)

def main():
    slowprint(f"{Fore.GREEN}[*] Initiating remote session...")
    animation(f"{Fore.YELLOW}[*] Establishing secure tunnel")
    slowprint(f"{Fore.CYAN}[+] Session established.")
    time.sleep(1)
    backdoor_menu()
    twist()

if __name__ == "__main__":
    main()
