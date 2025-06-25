#pragma once

#include "aes.hpp"

namespace boomerang {
    /**
     * @class Oracle
     * @brief Interface for an oracle that can encrypt and decrypt blocks of data.
     *        It also checks if a given key is correct.
     * @tparam Result The type of the result returned by the oracle.
     * @tparam Query The type of the query sent to the oracle.
     * @tparam Answer The type of the answer expected from the oracle.
     */
    template<typename Result, typename Query, typename Answer>
    class Oracle {
    public:
        /**
         * @brief Encrypts a block of data.
         * @param input The block of data to encrypt.
         * @return The encrypted block.
         */
        virtual Result encrypt(const Query) = 0;

        /**
         * @brief Decrypts a block of data.
         * @param input The block of data to decrypt.
         * @return The decrypted block.
         */
        virtual Result decrypt(const Query) = 0;

        /**
         * @TODO: Remove this check function and make few random queries to check for correctness.
         */
        virtual bool check(const Answer) = 0;
    };

    class AESOracle : public Oracle<block_t, block_t, aes_key_t> {
        AES aes = AES(AES_128);
        aes_key_t aes_key = random_key(AES_128);
    public:
        AESOracle() {}
    
        block_t encrypt(const block_t input) override {
            auto state = input;
            return aes.encrypt(aes_key, state, 5);
        }
    
        block_t decrypt(const block_t input) override {
            auto state = input;
            return aes.decrypt(aes_key, state, 5);
        }

        bool check(const aes_key_t key) override {
            for (auto w : aes_key) {
                print_word(w);
            }
            std::cout << std::endl;
            for (auto w : key) {
                print_word(w);
            }
            return key == aes_key;
        }
    };
    
    class RandomOracle : public Oracle<block_t, block_t, aes_key_t> {
        AES aes = AES(AES_128);
        aes_key_t aes_key = random_key(AES_128);
        size_t REPS = 3;
    public:
        RandomOracle() {}

        block_t encrypt(const block_t input) override {
            auto state = input;
            for (size_t i = 0; i < REPS; ++i) {
                state = aes.encrypt(aes_key, state);
            }
            return state;
        }
    
        block_t decrypt(const block_t input) override {
            auto state = input;
            for (size_t i = 0; i < REPS; ++i) {
                state = aes.decrypt(aes_key, state);
            }
            return state;
        }

        bool check(const aes_key_t key) override {
            for (auto w : aes_key) {
                print_word(w);
            }
            std::cout << std::endl;
            for (auto w : key) {
                print_word(w);
            }
            return key == aes_key;
        }
    };
}