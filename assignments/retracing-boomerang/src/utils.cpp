#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "utils.hpp"
#include "constants.hpp"

namespace ModularAES {
    byte_t gadd(byte_t a, byte_t b) {
        return a ^ b;
    }

    word_t gadd(word_t a, word_t b) {
        word_t result;
        for (size_t i = 0; i < NC; ++i) {
            result[i] = gadd(a[i], b[i]);
        }
        return result;
    }

    block_t gadd(block_t a, block_t b) {
        block_t result;
        for (size_t i = 0; i < NR; ++i) {
            result[i] = gadd(a[i], b[i]);
        }
        return result;
    }

    byte_t gmul(byte_t a, byte_t b) {
        if (!a || !b) return 0;
        return Alogtable[(Logtable[a] + Logtable[b])%255];  
    }

    word_t gmul(block_t a, word_t b) {
        word_t result = {0};
        for (size_t i = 0; i < NR; ++i) {
            result[i] = 0;
            for (size_t j = 0; j < NC; ++j) {
                result[i] ^= gmul(a[i][j], b[j]);
            }
        }
        return result;
    }

    word_t gmul(word_t a, block_t b) {
        word_t result = {0};
        for (size_t i = 0; i < NC; ++i) {
            result[i] = 0;
            for (size_t j = 0; j < NR; ++j) {
                result[i] ^= gmul(a[j], b[j][i]);
            }
        }
        return result;
    }

    block_t gmul(block_t a, block_t b) {
        block_t result = {0};
        for (size_t i = 0; i < NR; ++i) {
            result[i] = gmul(a[i], b);
        }
        return result;
    }

    byte_t random_byte() { return static_cast<byte_t>(rng() % 256); }

    word_t random_word() {
        word_t w;
        for (auto &b : w) {
            b = random_byte();
        }
        return w;
    }

    block_t random_block() {
        block_t b;
        for (auto &w : b) {
            w = random_word();
        }
        return b;
    }

    aes_key_t random_key() {
        aes_key_t k;
        for (auto &w : k) {
            w = random_word();
        }
        return k;
    }

    block_t hex_to_block(std::string &s) {
        block_t b;
        int p = 0;
        for (size_t j = 0; j < NC; ++j) {
            for (size_t i = 0; i < NR; ++i) {
                b[i][j] = static_cast<byte_t>(std::strtoul(s.substr(p, 2).c_str(), nullptr, 16));
                p += 2;
            }
        }
        return b;
    }

    std::string block_to_hex(block_t &b) {
        std::stringstream ss;
        for (size_t j = 0; j < NC; ++j) {
            for (size_t i = 0; i < NR; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b[i][j]);
            }
        }
        return ss.str();
    }
}