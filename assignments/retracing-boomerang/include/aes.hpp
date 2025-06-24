#pragma once

#include "utils.hpp"

namespace boomerang {
    class AES {
        block_t add_round_key(block_t, block_t);
        block_t sub_bytes(block_t, bool = false);
        block_t mix_columns(block_t, bool = false);
        std::vector<block_t> key_expansion(aes_key_t);

        size_t keylen = AES_128;
        size_t max_rounds = 10;

    public:
        AES(size_t = AES_128);
        block_t encrypt(const aes_key_t, const block_t, size_t = 0);
        block_t decrypt(const aes_key_t, const block_t, size_t = 0);
    };
}