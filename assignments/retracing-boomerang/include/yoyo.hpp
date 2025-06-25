#pragma once

#include <cassert>
#include "aes.hpp"
#include "oracle.hpp"

namespace boomerang {
    /**
     * @brief Swaps two unequal blocks of data at their first unequal column. Helper routine for the yoyo distinguisher.
     * @param a The first block to swap.
     * @param b The second block to swap.
     */
    void simple_swap(block_t&, block_t&);

    /**
     * @brief Implements the yoyo distinguisher for AES with 5 rounds.
     * @param oracle The oracle to use for encryption and decryption.
     * @param col The column to attack.
     * @param x0 The first block of the distinguishing pair.
     * @param x1 The second block of the distinguishing pair.
     * @return `true` if the distinguisher succeeds, `false` otherwise. `x0` and `x1` are populated with the distinguishing pair.
     */
    bool yoyo_distinguisher_5rd(Oracle<block_t, block_t, aes_key_t>&, size_t, block_t&, block_t&);
}