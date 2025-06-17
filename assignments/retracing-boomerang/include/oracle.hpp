#pragma once

#include "aes.hpp"

namespace boomerang {
    template<typename Result, typename Query, typename Answer>
    class Oracle {
    public:
        virtual Result encrypt(const Query) = 0;
        virtual Result decrypt(const Query) = 0;
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