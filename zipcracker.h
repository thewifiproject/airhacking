// zipcracker.h
#ifndef ZIPCRACKER_H
#define ZIPCRACKER_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

class ZipCracker {
public:
    ZipCracker(const std::string& zipFile, const std::string& wordlistFile);
    bool attemptCrack();

private:
    std::string zipFile;
    std::string wordlistFile;

    std::vector<std::string> loadWordlist();
    bool tryPassword(const std::string& password);
};

#endif // ZIPCRACKER_H
