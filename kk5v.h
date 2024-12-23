#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>

namespace kk5v {

    // Encrypt or decrypt a single byte with XOR encryption using a key
    char xorEncryptDecrypt(char byte, const std::string& key);

    // Caesar Cipher: Shift a single character by a certain shift amount
    char caesarEncryptDecrypt(char byte, int shift);

    // Encrypt a file using XOR + Caesar Cipher, applying to all file content
    void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key, int shift);

    // Encrypt the files in a given directory
    void encryptDirectory(const std::string& directory, const std::string& key, int shift);

} // namespace kk5v

#endif // KK5V_H
