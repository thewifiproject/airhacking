#include "CryptoUtils.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iostream>

std::string CryptoUtils::encrypt(const std::string& data, const std::string& key) {
    std::string encrypted = data;
    // Caesar Cipher + XOR
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] = (encrypted[i] + 3) ^ key[i % key.size()];
    }
    return encrypted;
}

std::string CryptoUtils::hash(const std::string& data) {
    // Simple hashing (not cryptographically secure)
    uint32_t hash = 0x811c9dc5; // FNV offset basis
    for (char c : data) {
        hash ^= c;
        hash *= 0x01000193; // FNV prime
    }
    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

std::vector<std::string> CryptoUtils::listFiles(const std::string& dirPath) {
    std::vector<std::string> files;
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((dirPath + "\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) return files;

    do {
        const std::string fileOrDir = findFileData.cFileName;
        if (fileOrDir != "." && fileOrDir != "..") {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                auto subFiles = listFiles(dirPath + "\\" + fileOrDir);
                files.insert(files.end(), subFiles.begin(), subFiles.end());
            } else {
                files.push_back(dirPath + "\\" + fileOrDir);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return files;
}

void CryptoUtils::processDirectory(const std::string& dirPath, const std::string& key) {
    auto files = listFiles(dirPath);
    for (const auto& file : files) {
        std::ifstream inFile(file, std::ios::binary);
        if (!inFile) continue;

        std::ostringstream buffer;
        buffer << inFile.rdbuf();
        std::string fileData = buffer.str();

        std::string encryptedData = encrypt(fileData, key);
        std::string fileHash = hash(fileData);

        std::ofstream outFile(file + ".protected", std::ios::binary);
        outFile << encryptedData;

        std::ofstream hashFile(file + ".hash", std::ios::binary);
        hashFile << fileHash;
    }
}
