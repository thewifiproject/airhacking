#ifndef PDFCRACKER_H
#define PDFCRACKER_H

#include <string>
#include <fstream>
#include <iostream>

class PDFCracker {
public:
    PDFCracker(const std::string& zipFile, const std::string& wordlistFile);
    void startBruteForce();

private:
    std::string zipFilePath;
    std::string wordlistPath;

    bool tryPassword(const std::string& password);
};

#endif // PDFCRACKER_H
