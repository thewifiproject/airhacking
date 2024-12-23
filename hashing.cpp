#include "hashing.h"
#include <iostream>
#include <bitset>
#include <sstream>
#include <iomanip>

std::string Hashing::sha1(const std::string& input) {
    std::vector<unsigned char> message(input.begin(), input.end());
    padMessage(message);

    std::vector<unsigned int> hashValues = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    size_t totalBlocks = message.size() / 64;
    for (size_t i = 0; i < totalBlocks; ++i) {
        std::vector<unsigned char> block(message.begin() + i * 64, message.begin() + (i + 1) * 64);
        processBlock(block, hashValues);
    }

    return toHex(hashValues);
}

void Hashing::padMessage(std::vector<unsigned char>& message) {
    size_t originalLength = message.size() * 8;
    message.push_back(0x80);

    while (message.size() % 64 != 56) {
        message.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        message.push_back(static_cast<unsigned char>((originalLength >> (i * 8)) & 0xFF));
    }
}

void Hashing::processBlock(const std::vector<unsigned char>& block, std::vector<unsigned int>& hashValues) {
    std::vector<unsigned int> w(80);

    for (size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<unsigned int>(block[i * 4]) << 24) |
               (static_cast<unsigned int>(block[i * 4 + 1]) << 16) |
               (static_cast<unsigned int>(block[i * 4 + 2]) << 8) |
               (static_cast<unsigned int>(block[i * 4 + 3]));
    }

    for (size_t i = 16; i < 80; ++i) {
        w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }

    unsigned int a = hashValues[0];
    unsigned int b = hashValues[1];
    unsigned int c = hashValues[2];
    unsigned int d = hashValues[3];
    unsigned int e = hashValues[4];

    for (size_t i = 0; i < 80; ++i) {
        unsigned int f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        unsigned int temp = (a << 5) | (a >> 27);
        temp += f + e + k + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }

    hashValues[0] += a;
    hashValues[1] += b;
    hashValues[2] += c;
    hashValues[3] += d;
    hashValues[4] += e;
}

std::string Hashing::toHex(const std::vector<unsigned int>& hashValues) {
    std::ostringstream stream;
    for (unsigned int value : hashValues) {
        stream << std::setw(8) << std::setfill('0') << std::hex << value;
    }
    return stream.str();
}
