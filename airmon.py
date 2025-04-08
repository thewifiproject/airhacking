import argparse
import subprocess
import sys

def set_monitor_mode(interface, mode):
    if not interface.startswith("wlan"):
        print("Only wlan interfaces are supported.")
        sys.exit(1)

    try:
        if mode == "on":
            subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
            print(f"Monitor mode enabled on {interface}.")
        elif mode == "off":
            subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", interface, "mode", "managed"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
            print(f"Monitor mode disabled on {interface}.")
        else:
            print("Invalid mode. Use 'on' or 'off'.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Failed to set monitor mode: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Set monitor mode on a wlan interface.")
    parser.add_argument("set", help="Set monitor mode on or off")
    parser.add_argument("interface", help="The wlan interface to configure (e.g., wlan0)")
    parser.add_argument("mode", choices=["on", "off"], help="Enable or disable monitor mode")

    args = parser.parse_args()

    set_monitor_mode(args.interface, args.mode)

if __name__ == "__main__":
    main()
