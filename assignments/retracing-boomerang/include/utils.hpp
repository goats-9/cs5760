#pragma once

#include <algorithm>
#include <cassert>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <gnutls/crypto.h>
#include "constants.hpp"

namespace boomerang {
    /* Galois field operators */
    constexpr byte_t MIN_POLY = 0x1b;   // Minimal polynomial of GF(2^8)

    // Addition in GF(2^8)
    byte_t gadd(byte_t, byte_t);
    word_t gadd(word_t, word_t);
    block_t gadd(block_t, block_t);

    // Multiplication in GF(2^8)
    byte_t gmul(byte_t, byte_t);
    word_t gmul(word_t, block_t);
    block_t gmul(block_t, block_t);

    // Exponentiation in GF(2^8) and multiplicative inverse
    byte_t gexp(byte_t, size_t);
    byte_t ginv(byte_t);

    /* Utility functions */
    // Random number generation
    byte_t random_byte();
    word_t random_word();
    block_t random_block();
    aes_key_t random_key(size_t);

    // Shift row operations
    word_t shift_row(word_t, int);
    block_t shift_rows(block_t, bool = false);

    // Print functions
    void print_word(word_t &);
    void print_block(block_t &);

    // Conversion
    block_t hex_to_block(std::string &);
    aes_key_t hex_to_key(std::string &);
    std::string block_to_hex(block_t &);
}