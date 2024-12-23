#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>

class KK5V
{
public:
    static const std::string MAGIC_KEY;

    // Function to perform Caesar Cipher encryption
    static std::string caesarCipher(const std::string& input, int shift);

    // Function to perform XOR encryption
    static std::string xorCipher(const std::string& input, const std::string& key);

    // Function to encrypt a file
    static bool encryptFile(const std::string& filePath, const std::string& outputFilePath);

    // Function to process files in the specified directory using fstream
    static void processDirectory(const std::string& directoryPath);
};

#endif // KK5V_H
