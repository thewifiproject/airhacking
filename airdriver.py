import os
import json
import subprocess
import time
from colorama import Fore, Style, init

init(autoreset=True)

COOKIES_FILE = "/tmp/reboot_status.json"
INTERFACES_COOKIE = "/tmp/initial_interfaces.json"

def run_command(command, prompt=None, return_output=False, background=False):
    if prompt:
        print(Fore.BLUE + prompt)
    if background:
        subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    result = subprocess.run(command, shell=True, capture_output=return_output, text=True)
    if return_output:
        return result.stdout.strip()
    if result.returncode != 0:
        print(Fore.RED + "Error: Command failed!")
        exit(1)

def get_interfaces():
    output = run_command("ls /sys/class/net", return_output=True)
    return output.split()

def save_initial_interfaces():
    interfaces = get_interfaces()
    with open(INTERFACES_COOKIE, "w") as f:
        json.dump(interfaces, f)

def get_new_interface():
    if not os.path.exists(INTERFACES_COOKIE):
        return None
    with open(INTERFACES_COOKIE, "r") as f:
        initial = set(json.load(f))
    final = set(get_interfaces())
    new_interfaces = list(final - initial)
    return new_interfaces[0] if new_interfaces else None

def run_airodump_test(interface):
    run_command(f"sudo ip link set {interface} down")
    run_command(f"sudo iw dev {interface} set type monitor")
    run_command(f"sudo ip link set {interface} up")
    output = subprocess.run(f"timeout 10 airodump-ng {interface}", shell=True, capture_output=True, text=True)
    run_command(f"sudo ip link set {interface} down")
    run_command(f"sudo iw dev {interface} set type managed")
    run_command(f"sudo ip link set {interface} up")
    if "WPA" in output.stdout or "WEP" in output.stdout or "ESSID" in output.stdout:
        print(Fore.GREEN + "Installation Success: Networks detected.")
    else:
        print(Fore.RED + "Installation Failed: No networks detected.")

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
    print(Fore.YELLOW + "The system will now reboot! Continue? [Y/n]: ", end="")
    choice = input().strip().lower()
    if choice in ("y", "yes", ""):
        set_reboot_status(True)
        run_command("sudo reboot", "Rebooting the system...")
        exit(0)
    else:
        print(Fore.RED + "Exiting installer.")
        exit(0)

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
        if "8814" in selected_device:
            return "8814AU"
        else:
            return "8812AU"
    except (IndexError, ValueError):
        print(Fore.RED + "Invalid selection. Exiting.")
        exit(1)

def install_driver(driver_type):
    run_command("sudo apt update", "Updating package lists...")
    run_command("sudo apt install -y realtek-rtl88xxau-dkms", "Installing DKMS package...")

    if driver_type == "8812AU":
        run_command("git clone https://github.com/aircrack-ng/rtl8812au.git", "Cloning the driver repository...")
        os.chdir("rtl8812au")
        run_command("make", "Building the driver...")
        run_command("sudo make install", "Installing the driver...")
    else:
        print(Fore.YELLOW + "RTL8814AU selected: Cloning the repository...")
        run_command("git clone https://github.com/aircrack-ng/rtl8814au.git", "Cloning RTL8814AU repository...")
        os.chdir("rtl8814au")
        print(Fore.YELLOW + "Running make command with sudo...")
        run_command("sudo make", "Building the RTL8814AU driver...")
        print(Fore.YELLOW + "Running make install command with sudo...")
        run_command("sudo make install", "Installing RTL8814AU driver...")

def main():
    print(Fore.GREEN + "Starting Realtek Installer...")

    if not check_reboot_status():
        time.sleep(5)
        save_initial_interfaces()
        chipset = list_adapters()
        system_update_upgrade()
        reboot_system()
    else:
        print(Fore.YELLOW + "Do you still want to continue? [Y/n]: ", end="")
        choice = input().strip().lower()
        if choice not in ("y", "yes", ""):
            print(Fore.RED + "Exiting installer.")
            exit(0)
        chipset = list_adapters()

    install_driver(chipset)

    print(Fore.GREEN + "Waiting for device initialization...")
    time.sleep(10)
    new_iface = get_new_interface()

    if not new_iface:
        print(Fore.RED + "No new interface detected after installation.")
        exit(1)

    print(Fore.GREEN + f"Detected new interface: {new_iface}")
    print(Fore.GREEN + "Testing with airodump-ng...")
    run_airodump_test(new_iface)

    # Cleanup cookie files
    if os.path.exists(COOKIES_FILE):
        os.remove(COOKIES_FILE)
    if os.path.exists(INTERFACES_COOKIE):
        os.remove(INTERFACES_COOKIE)

    print(Fore.GREEN + "Done. You may now use your wireless adapter.")

if __name__ == "__main__":
    main()
