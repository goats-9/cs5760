#include "utils.hpp"

namespace boomerang {
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
        if (a && b) return Alogtable[(Logtable[a] + Logtable[b]) % 255];
        return 0;
    }

    word_t gmul(word_t a, block_t b) {
        word_t result;
        for (size_t i = 0; i < NC; ++i) {
            result[i] = 0;
            for (size_t j = 0; j < NR; ++j) {
                result[i] ^= gmul(a[j], b[j][i]);
            }
        }
        return result;
    }

    block_t gmul(block_t a, block_t b) {
        block_t result;
        for (size_t i = 0; i < NR; ++i) {
            result[i] = gmul(a[i], b);
        }
        return result;
    }

    byte_t ginv(byte_t a) {
        return Alogtable[(255 - Logtable[a]) % 255];
    }

    byte_t random_byte() {
        byte_t out;
        gnutls_rnd(GNUTLS_RND_KEY, &out, sizeof(out));
        return out;
    }

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

    word_t shift_row(word_t word, int off) {
        off %= NC;
        if (off < 0) off += NC;
        std::rotate(word.begin(), word.begin() + off, word.end());
        return word;
    }

    block_t shift_rows(block_t state, bool inv) {
        for (size_t i = 1; i < NR; ++i) {
            int x = inv ? -i : i;
            state[i] = shift_row(state[i], x);
        }
        return state;
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
            for (size_t i = 0; i < NR; ++i) {
                k[i] = std::stoul(s.substr(p, 2).c_str(), nullptr, 16);
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
