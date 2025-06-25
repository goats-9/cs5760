#pragma once

#include "utils.hpp"

namespace boomerang {
    /**
     * @class AES
     * @brief Implementation of AES block cipher.
     */
    class AES {
        block_t add_round_key(block_t, block_t);
        block_t sub_bytes(block_t, bool = false);
        block_t mix_columns(block_t, bool = false);
        std::vector<block_t> key_expansion(aes_key_t);

        size_t keylen = AES_128;
        size_t max_rounds = 10;

    public:
        /**
         * @brief Constructor for AES cipher.
         * @param keylen Length of the key in bytes (default is 16 bytes for AES-128).
         */
        AES(size_t = AES_128);

        /**
         * @brief Encrypts a block of data using the AES cipher.
         * @param key The AES key to use for encryption.
         * @param block The block of data to encrypt.
         * @param rounds Number of rounds to perform (default is 10 for AES-128).
         * @return The encrypted block.
         */
        block_t encrypt(const aes_key_t, const block_t, size_t = 0);

        /**
         * @brief Decrypts a block of data using the AES cipher.
         * @param key The AES key to use for decryption.
         * @param block The block of data to decrypt.
         * @param rounds Number of rounds to perform (default is 10 for AES-128).
         * @return The decrypted block.
         */
        block_t decrypt(const aes_key_t, const block_t, size_t = 0);
    };
}