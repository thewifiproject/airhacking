// zipcracker.cpp
#include "zipcracker.h"

ZipCracker::ZipCracker(const std::string& zipFile, const std::string& wordlistFile)
    : zipFile(zipFile), wordlistFile(wordlistFile) {}

std::vector<std::string> ZipCracker::loadWordlist() {
    std::vector<std::string> wordlist;
    std::ifstream file(wordlistFile);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open wordlist file: " + wordlistFile);
    }

    std::string line;
    while (std::getline(file, line)) {
        wordlist.push_back(line);
    }

    file.close();
    return wordlist;
}

bool ZipCracker::tryPassword(const std::string& password) {
    // This is a placeholder for actual password testing logic.
    // Replace this with ZIP decryption testing logic as necessary.
    std::cout << "Trying password: " << password << std::endl;

    // Simulation: Replace this with actual ZIP decryption test
    return password == "correct_password";
}

bool ZipCracker::attemptCrack() {
    auto wordlist = loadWordlist();
    for (const auto& password : wordlist) {
        if (tryPassword(password)) {
            std::cout << "Password found: " << password << std::endl;
            return true;
        }
    }

    std::cout << "Password not found in wordlist." << std::endl;
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " -z <zipfile> <wordlist>" << std::endl;
        return 1;
    }

    std::string zipFile;
    std::string wordlistFile;

    if (std::string(argv[1]) == "-z") {
        zipFile = argv[2];
        wordlistFile = argv[3];
    } else {
        std::cerr << "Invalid arguments. Usage: " << argv[0] << " -z <zipfile> <wordlist>" << std::endl;
        return 1;
    }

    try {
        ZipCracker cracker(zipFile, wordlistFile);
        cracker.attemptCrack();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
