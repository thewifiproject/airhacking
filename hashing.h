#ifndef HASHING_H
#define HASHING_H

#include <string>
#include <vector>

class Hashing {
public:
    static std::string sha1(const std::string& input);  // SHA1 Hashing method
private:
    static void padMessage(std::vector<unsigned char>& message);  // Padding for SHA1
    static void processBlock(const std::vector<unsigned char>& block, std::vector<unsigned int>& hashValues);
    static std::string toHex(const std::vector<unsigned int>& hashValues);
};

#endif
