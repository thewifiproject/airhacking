#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>

// Function to get a list of files in a given directory
std::vector<std::string> getFilesInDirectory(const std::string& directory);

// XOR Encryption Function
void encryptFileXOR(const std::string& filePath);

// Caesar Cipher Encryption Function
void encryptFileCaesar(const std::string& filePath);

#endif
