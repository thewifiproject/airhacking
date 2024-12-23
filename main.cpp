#include <iostream>
#include <string>
#include "pdfcracker.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: pdfcracker -f <pdf_file> <wordlist_file>" << std::endl;
        return 1;
    }

    std::string pdfFile;
    std::string wordlistFile;

    if (std::string(argv[1]) == "-f") {
        pdfFile = argv[2];
        wordlistFile = argv[3];
    }

    PDFCracker cracker(pdfFile, wordlistFile);
    cracker.crackPassword();

    return 0;
}
