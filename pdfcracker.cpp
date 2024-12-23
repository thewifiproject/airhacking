#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include "pdfcracker.h"

PDFCracker::PDFCracker(const std::string& pdfFile, const std::string& wordlistFile)
    : pdfFile(pdfFile), wordlistFile(wordlistFile) {}

std::vector<std::string> PDFCracker::readWordlist() {
    std::vector<std::string> wordlist;
    std::ifstream file(wordlistFile);
    std::string line;
    
    if (!file.is_open()) {
        std::cerr << "Error opening wordlist file!" << std::endl;
        return wordlist;
    }

    while (std::getline(file, line)) {
        wordlist.push_back(line);
    }

    file.close();
    return wordlist;
}

bool PDFCracker::testPassword(const std::string& password) {
    std::string command = "pdftk " + pdfFile + " input_pw " + password + " dump_data output /dev/null";
    int result = system(command.c_str());
    return result == 0;  // 0 means success in many command-line utilities
}

void PDFCracker::crackPassword() {
    std::vector<std::string> wordlist = readWordlist();

    for (const std::string& password : wordlist) {
        std::cout << "Testing password: " << password << std::endl;
        if (testPassword(password)) {
            std::cout << "Password found: " << password << std::endl;
            return;
        }
    }

    std::cout << "No password found in the wordlist." << std::endl;
}
