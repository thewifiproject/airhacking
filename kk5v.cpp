#include "kk5v.h"
#include <iostream>
#include <fstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>

const std::string KK5V::MAGIC_KEY = "magicspell";  // XOR key

// Caesar Cipher Implementation
std::string KK5V::caesarCipher(const std::string& input, int shift)
{
    std::string result = input;
    for (size_t i = 0; i < input.size(); i++)
    {
        if (isalpha(input[i]))
        {
            char base = islower(input[i]) ? 'a' : 'A';
            result[i] = (input[i] - base + shift) % 26 + base;
        }
        else
        {
            result[i] = input[i];
        }
    }
    return result;
}

// XOR Cipher Implementation
std::string KK5V::xorCipher(const std::string& input, const std::string& key)
{
    std::string result = input;
    size_t keyLength = key.length();
    for (size_t i = 0; i < input.size(); i++)
    {
        result[i] = input[i] ^ key[i % keyLength];
    }
    return result;
}

// Encrypt a file by applying Caesar and XOR ciphers
bool KK5V::encryptFile(const std::string& filePath, const std::string& outputFilePath)
{
    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile.is_open())
    {
        return false;
    }

    std::vector<char> fileData((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // First apply Caesar Cipher with shift = 3 (example)
    std::string encryptedData(fileData.begin(), fileData.end());
    encryptedData = caesarCipher(encryptedData, 3);

    // Then apply XOR Cipher with the MAGIC_KEY
    encryptedData = xorCipher(encryptedData, MAGIC_KEY);

    // Write the encrypted data to the output file with .protected extension
    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile.is_open())
    {
        return false;
    }

    outputFile.write(encryptedData.c_str(), encryptedData.size());
    outputFile.close();

    return true;
}

// Process directory to find files and encrypt them using fstream
void KK5V::processDirectory(const std::string& directoryPath)
{
    DIR* dir = opendir(directoryPath.c_str());
    if (dir == nullptr)
    {
        std::cerr << "Error opening directory: " << directoryPath << std::endl;
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        // Skip . and .. directories
        if (entry->d_name[0] == '.')
        {
            continue;
        }

        std::string filePath = directoryPath + "/" + entry->d_name;
        struct stat fileInfo;
        if (stat(filePath.c_str(), &fileInfo) == 0 && S_ISREG(fileInfo.st_mode)) // Check if it's a file
        {
            std::string encryptedFilePath = filePath + ".protected";
            if (encryptFile(filePath, encryptedFilePath))
            {
                std::cout << "Encrypted: " << filePath << std::endl;
            }
            else
            {
                std::cout << "Failed to encrypt: " << filePath << std::endl;
            }
        }
    }

    closedir(dir);
}
