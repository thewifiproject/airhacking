#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>
#include <windows.h>

class KK5V
{
public:
    KK5V(const std::string& key);

    // Method to encrypt/decrypt a file
    void encryptFile(const std::string& inputFilePath, const std::string& outputFilePath);

    // Method to process files in the directories
    void encryptDirectory(const std::string& directoryPath);

private:
    std::string key;
    std::vector<unsigned char> xorEncryptDecrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> caesarEncryptDecrypt(const std::vector<unsigned char>& data);
    void processFile(const std::string& filePath, const std::string& outputFilePath);
};

#endif // KK5V_H
