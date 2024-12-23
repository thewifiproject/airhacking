#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>

class CryptoUtils {
public:
    static void processDirectory(const std::string& dirPath, const std::string& key);

private:
    static void encryptFile(const std::string& filePath, const std::string& key);
    static std::string encrypt(const std::string& data, const std::string& key);
    static std::string hash(const std::string& data);
};

#endif // CRYPTO_UTILS_H
