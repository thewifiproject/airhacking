#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>

// Function to XOR encrypt a given buffer with a key
std::vector<unsigned char> xorEncrypt(const std::vector<unsigned char>& input, const std::string& key);

// Function to apply Caesar cipher to a given buffer
std::vector<unsigned char> caesarCipherEncrypt(const std::vector<unsigned char>& input, int shift);

// Function to encrypt a file with XOR and Caesar cipher
void encryptFile(const std::string& filePath, const std::string& key, int caesarShift);

// Helper function to read the contents of a file
std::vector<unsigned char> readFile(const std::string& filePath);

// Helper function to write encrypted data to a file
void writeFile(const std::string& filePath, const std::vector<unsigned char>& data);

#endif // KK5V_H
