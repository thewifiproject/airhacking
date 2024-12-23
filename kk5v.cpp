#include "kk5v.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>

KK5V::KK5V(const std::string& key) : key(key) {}

void KK5V::encryptFile(const std::string& inputFilePath, const std::string& outputFilePath)
{
    // Read file content into a buffer using fstream
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile)
    {
        std::cerr << "Error opening file: " << inputFilePath << std::endl;
        return;
    }
    
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
    // Search for files in the directory using Windows API
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((directoryPath + "\\*").c_str(), &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error accessing directory: " << directoryPath << std::endl;
        return;
    }
    
    do
    {
        const std::string fileName = findFileData.cFileName;
        
        // Skip "." and ".."
        if (fileName == "." || fileName == "..")
            continue;
        
        std::string fullFilePath = directoryPath + "\\" + fileName;
        
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // Recurse into subdirectory
            encryptDirectory(fullFilePath);
        }
        else
        {
            // Encrypt regular file
            std::string outputFilePath = fullFilePath + ".protected";
            encryptFile(fullFilePath, outputFilePath);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);
    
    FindClose(hFind);
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
