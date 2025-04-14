import os
import json
import subprocess
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

COOKIES_FILE = "/tmp/reboot_status.json"

def run_command(command, prompt=None, return_output=False):
    if prompt:
        print(Fore.BLUE + prompt)
    result = subprocess.run(command, shell=True, capture_output=return_output, text=True)
    if return_output:
        return result.stdout.strip()
    if result.returncode != 0:
        print(Fore.RED + "Error: Command failed!")
        exit(1)

def system_update_upgrade():
    run_command("sudo apt update", "Updating package lists...")
    run_command("sudo apt upgrade -y", "Upgrading packages...")
    run_command("sudo apt dist-upgrade -y", "Performing distribution upgrade...")

def list_adapters():
    print(Fore.BLUE + "Listing compatible adapters...")
    output = run_command("lsusb", "Detected USB devices:", return_output=True)
    devices = output.splitlines()
    
    print(Fore.CYAN + "Available USB devices:")
    for idx, device in enumerate(devices, start=1):
        print(Fore.YELLOW + f"[{idx}] {device}")
    
    print(Fore.CYAN + "Select which one: ", end="")
    choice = input().strip()
    
    try:
        selected_device = devices[int(choice) - 1]
        print(Fore.GREEN + f"You selected: {selected_device}")
    except (IndexError, ValueError):
        print(Fore.RED + "Invalid selection. Exiting.")
        exit(1)

def choose_chipset():
    print(Fore.CYAN + "Which Realtek chipset are you using?")
    print(Fore.YELLOW + "[1] RTL8812AU")
    print(Fore.YELLOW + "[2] RTL8814AU")
    choice = input(Fore.CYAN + "Enter choice [1/2]: ").strip()
    
    if choice == "1":
        return "rtl8812au"
    elif choice == "2":
        return "rtl8814au"
    else:
        print(Fore.RED + "Invalid choice. Exiting.")
        exit(1)

def check_reboot_status():
    if os.path.exists(COOKIES_FILE):
        with open(COOKIES_FILE, "r") as f:
            data = json.load(f)
        if data.get("rebooted", False):
            return True
    return False

def set_reboot_status(status):
    with open(COOKIES_FILE, "w") as f:
        json.dump({"rebooted": status}, f)

def reboot_system():
    print(Fore.YELLOW + "The system will be now rebooted! Do you want to continue? [Y/n]: ", end="")
    choice = input().strip().lower()
    if choice in ("y", "yes", ""):
        set_reboot_status(True)
        run_command("sudo reboot", "Rebooting the system...")
        exit(0)
    else:
        print(Fore.RED + "Exiting installer.")
        exit(0)

def install_driver(chipset):
    run_command("sudo apt update", "Updating package lists...")
    run_command("sudo apt install -y realtek-rtl88xxau-dkms", "Installing DKMS package...")

    if chipset == "rtl8812au":
        run_command("git clone https://github.com/aircrack-ng/rtl8812au.git", "Cloning the RTL8812AU driver repository...")
        os.chdir("rtl8812au")
        run_command("make", "Building the RTL8812AU driver...")
        run_command("sudo make install", "Installing the RTL8812AU driver...")

def main():
    print(Fore.GREEN + "Starting Realtek RTL88xxAU Installer...")

    if not check_reboot_status():
        list_adapters()
        system_update_upgrade()
        reboot_system()
    else:
        print(Fore.YELLOW + "Do you still want to continue? [Y/n]: ", end="")
        choice = input().strip().lower()
        if choice not in ("y", "yes", ""):
            print(Fore.RED + "Exiting installer.")
            exit(0)

    # Choose chipset
    chipset = choose_chipset()
    
    # Install the appropriate driver
    install_driver(chipset)

    print(Fore.GREEN + "Replug your adapter to make it work. Waiting for 30 seconds...")
    time.sleep(30)
    print(Fore.GREEN + "Goodbye!")

if __name__ == "__main__":
    main()
