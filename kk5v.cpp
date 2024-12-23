#include "kk5v.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

// XOR encryption function
std::vector<unsigned char> xorEncrypt(const std::vector<unsigned char>& input, const std::string& key) {
    std::vector<unsigned char> result(input.size());
    size_t keyLength = key.length();
    for (size_t i = 0; i < input.size(); ++i) {
        result[i] = input[i] ^ key[i % keyLength];
    }
    return result;
}

// Caesar cipher encryption function
std::vector<unsigned char> caesarCipherEncrypt(const std::vector<unsigned char>& input, int shift) {
    std::vector<unsigned char> result(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        result[i] = input[i] + shift; // simple Caesar shift
    }
    return result;
}

// Encrypt a file using XOR and Caesar cipher
void encryptFile(const std::string& filePath, const std::string& key, int caesarShift) {
    std::vector<unsigned char> data = readFile(filePath);

    // Step 1: XOR encryption
    std::vector<unsigned char> xorEncryptedData = xorEncrypt(data, key);

    // Step 2: Caesar cipher encryption
    std::vector<unsigned char> finalEncryptedData = caesarCipherEncrypt(xorEncryptedData, caesarShift);

    // Save encrypted data with .protected extension
    std::string encryptedFilePath = filePath + ".protected";
    writeFile(encryptedFilePath, finalEncryptedData);
}

// Read file contents into a buffer using fstream
std::vector<unsigned char> readFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    // Get the file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file contents into a vector
    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    return buffer;
}

// Write encrypted data to a file using fstream
void writeFile(const std::string& filePath, const std::vector<unsigned char>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to write to file: " + filePath);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}
