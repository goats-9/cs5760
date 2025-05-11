#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <random>
#include <vector>

namespace modular_aes {
    /* Constants */
    constexpr size_t NR = 4;
    constexpr size_t NC = 4;
    constexpr size_t NK_128 = 4;
    constexpr size_t NK_192 = 6;
    constexpr size_t NK_256 = 8;

    /* Typedefs and structs */
    using byte_t = uint8_t;
    using word_t = std::array<byte_t, NC>;
    using block_t = std::array<word_t, NR>;
    using aes_key_t = std::vector<word_t>;
    using aes_step_t = std::function<block_t(block_t, block_t, bool)>;
    using aes_key_schedule_t = std::function<std::vector<block_t>(aes_key_t)>;

    inline std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    inline std::uniform_int_distribution<byte_t> dist(0, 255);

    /* Galois field operators */
    constexpr byte_t MIN_POLY = 0x1b;   // Minimal polynomial of GF(2^8)
    constexpr byte_t GEN = 0x02;        // Generator of GF(2^8)

    // Addition in GF(2^8)
    byte_t gadd(byte_t a, byte_t b);
    word_t gadd(word_t a, word_t b);
    block_t gadd(block_t a, block_t b);

    // Multiplication in GF(2^8)
    byte_t gmul(byte_t a, byte_t b);
    word_t gmul(word_t a, block_t b);
    block_t gmul(block_t a, block_t b);

    /* Utility functions */
    // Random number generation
    byte_t random_byte();
    word_t random_word();
    block_t random_block();
    aes_key_t random_key(size_t len);

    // Print functions
    void print_word(word_t &w);
    void print_block(block_t &b);

    // Conversion
    block_t hex_to_block(std::string &s);
    aes_key_t hex_to_key(std::string &s);
    std::string block_to_hex(block_t &);
}