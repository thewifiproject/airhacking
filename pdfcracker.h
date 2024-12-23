#ifndef PDFCRACKER_H
#define PDFCRACKER_H

#include <string>
#include <vector>

class PDFCracker {
public:
    PDFCracker(const std::string& pdfFile, const std::string& wordlistFile);
    void crackPassword();

private:
    std::string pdfFile;
    std::string wordlistFile;
    std::vector<std::string> readWordlist();
    bool testPassword(const std::string& password);
};

#endif
