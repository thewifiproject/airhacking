#include "hashing.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <bitset>
#include <cstring>
#include <cassert>

#define SHA1_BLOCK_SIZE 64  // SHA1 processes 512 bits at a time (64 bytes)

// SHA1 constants
const unsigned int H0 = 0x67452301;
const unsigned int H1 = 0xEFCDAB89;
const unsigned int H2 = 0x98BADCFE;
const unsigned int H3 = 0x10325476;
const unsigned int H4 = 0xC3D2E1F0;

// Rotate left (circular left shift) operation
inline unsigned int rotateLeft(unsigned int value, unsigned int shift) {
    return (value << shift) | (value >> (32 - shift));
}

// Padding the message to ensure it's a multiple of 512 bits
void Hashing::padMessage(std::vector<unsigned char>& message) {
    size_t originalSize = message.size() * 8;
    
    // Append '1' bit to the message
    message.push_back(0x80);
    
    // Pad with '0' bits until the message length (in bits) is 64 bits less than a multiple of 512
    while (message.size() % SHA1_BLOCK_SIZE != 56) {
        message.push_back(0x00);
    }
    
    // Append the length of the original message (in bits), as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        message.push_back(static_cast<unsigned char>((originalSize >> (i * 8)) & 0xFF));
    }
}

// Process a 512-bit block and update hash values
void Hashing::processBlock(const std::vector<unsigned char>& block, std::vector<unsigned int>& hashValues) {
    // Prepare message schedule (80 words, each 32 bits)
    unsigned int w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 4; ++j) {
            w[i] |= (block[i * 4 + j] << (24 - j * 8));
        }
    }

    // Extend the message schedule to 80 words
    for (int i = 16; i < 80; ++i) {
        w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    unsigned int a = hashValues[0];
    unsigned int b = hashValues[1];
    unsigned int c = hashValues[2];
    unsigned int d = hashValues[3];
    unsigned int e = hashValues[4];

    for (int i = 0; i < 80; ++i) {
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

        unsigned int temp = rotateLeft(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotateLeft(b, 30);
        b = a;
        a = temp;
    }

    // Update hash values
    hashValues[0] += a;
    hashValues[1] += b;
    hashValues[2] += c;
    hashValues[3] += d;
    hashValues[4] += e;
}

// Convert the hash values to a hex string
std::string Hashing::toHex(const std::vector<unsigned int>& hashValues) {
    std::stringstream ss;
    for (unsigned int val : hashValues) {
        ss << std::setfill('0') << std::setw(8) << std::hex << val;
    }
    return ss.str();
}

// The main method that hashes the input using SHA1
std::string Hashing::sha1(const std::string& input) {
    // Convert input string to a vector of bytes
    std::vector<unsigned char> message(input.begin(), input.end());
    
    // Pad the message according to SHA1 specifications
    padMessage(message);
    
    // Initialize hash values
    std::vector<unsigned int> hashValues = { H0, H1, H2, H3, H4 };
    
    // Process the message in 512-bit blocks (64-byte blocks)
    size_t blockCount = message.size() / SHA1_BLOCK_SIZE;
    for (size_t i = 0; i < blockCount; ++i) {
        std::vector<unsigned char> block(message.begin() + i * SHA1_BLOCK_SIZE, message.begin() + (i + 1) * SHA1_BLOCK_SIZE);
        processBlock(block, hashValues);
    }
    
    // Return the final hash as a hex string
    return toHex(hashValues);
}
