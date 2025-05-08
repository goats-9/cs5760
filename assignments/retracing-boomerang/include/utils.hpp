#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <random>
#include <vector>

namespace ModularAES {
    /* Constants */
    constexpr size_t NR = 4;
    constexpr size_t NC = 4;
    constexpr size_t NK = 4;
    inline std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());

    /* Typedefs and structs */
    using byte_t = unsigned char;
    using word_t = std::array<byte_t, NC>;
    using block_t = std::array<word_t, NR>;
    using aes_key_t = std::array<std::array<byte_t, NK>, NR>;
    using aes_step_t = std::function<void(block_t&, aes_key_t&)>;
    using aes_key_schedule_t = std::function<std::vector<block_t>(aes_key_t&, size_t)>;

    /* Galois field operators */
    // Addition in GF(2^8)
    byte_t gadd(byte_t a, byte_t b);
    word_t gadd(word_t a, word_t b);
    block_t gadd(block_t a, block_t b);

    // Multiplication in GF(2^8)
    byte_t gmul(byte_t a, byte_t b);
    word_t gmul(block_t a, word_t b);
    word_t gmul(word_t a, block_t b);
    block_t gmul(block_t a, block_t b);

    /* Utility functions */
    // Random number generation
    byte_t random_byte();
    word_t random_word();
    block_t random_block();
    aes_key_t random_key();

    // Conversion
    block_t hex_to_block(std::string &s);
    std::string block_to_hex(block_t &);
}