#include <cassert>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include "utils.hpp"
#include "constants.hpp"

namespace modular_aes {
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
        byte_t result = 0;
        for (; b; b >>= 1) {
            if (b & 1) {
                result ^= a;
            } 
            if (a & 0x80) {
                a = (a << 1) ^ MIN_POLY;
            } else {
                a <<= 1;
            }
        }
        return result;
    }

    word_t gmul(word_t a, block_t b) {
        word_t result;
        for (size_t i = 0; i < NC; ++i) {
            result[i] = 0;
            for (size_t j = 0; j < NR; ++j) {
                result[i] = gadd(result[i], gmul(a[j], b[j][i]));
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

    byte_t random_byte() { return dist(rng); }

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

    aes_key_t random_key(size_t len) {
        aes_key_t k(len);
        for (auto &w : k) {
            w = random_word();
        }
        return k;
    }

    void print_word(word_t &w) {
        for (size_t i = 0; i < NC; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(w[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    void print_block(block_t &b) {
        for (auto &w : b) {
            print_word(w);
        }
    }

    block_t hex_to_block(std::string &s) {
        size_t n = s.size();
        assert(n == 32);
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

    aes_key_t hex_to_key(std::string &s) {
        size_t n = s.size();
        assert(n == 32 || n == 48 || n == 64);
        aes_key_t key(n / 8);
        int p = 0;
        for (auto& k : key) {
            for (size_t i = 0; i < NC; ++i) {
                k[i] = static_cast<byte_t>(std::strtoul(s.substr(p, 2).c_str(), nullptr, 16));
                p += 2;
            }
        }
        return key;
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