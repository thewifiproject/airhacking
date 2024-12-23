#include "kk5v.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

KK5V::KK5V(const std::string& key) : key(key) {}

void KK5V::encryptFile(const std::string& inputFilePath, const std::string& outputFilePath)
{
    // Read file content into a buffer
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    
    // Apply XOR encryption followed by Caesar encryption
    buffer = xorEncryptDecrypt(buffer);
    buffer = caesarEncryptDecrypt(buffer);
    
    // Write encrypted data to the output file
    std::ofstream outputFile(outputFilePath, std::ios::binary);
    outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
}

void KK5V::encryptDirectory(const std::string& directoryPath)
{
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath))
    {
        if (entry.is_regular_file())
        {
            std::string filePath = entry.path().string();
            std::string outputFilePath = filePath + ".protected"; // Save with ".protected" extension
            encryptFile(filePath, outputFilePath);
        }
    }
}

std::vector<unsigned char> KK5V::xorEncryptDecrypt(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> result = data;
    size_t keyLength = key.size();
    
    for (size_t i = 0; i < data.size(); ++i)
    {
        result[i] = data[i] ^ key[i % keyLength];  // XOR encryption
    }
    
    return result;
}

std::vector<unsigned char> KK5V::caesarEncryptDecrypt(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> result = data;
    
    for (size_t i = 0; i < data.size(); ++i)
    {
        result[i] = data[i] + 3; // Caesar cipher: shift by 3
    }
    
    return result;
}

void KK5V::processFile(const std::string& filePath, const std::string& outputFilePath)
{
    encryptFile(filePath, outputFilePath);
}
