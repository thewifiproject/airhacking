#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>

class CryptoUtils {
public:
    static std::string encrypt(const std::string& data, const std::string& key);
    static std::string hash(const std::string& data);
    static void processDirectory(const std::string& dirPath, const std::string& key);
private:
    static std::vector<std::string> listFiles(const std::string& dirPath);
};

#endif // CRYPTO_UTILS_H
