#pragma once
#include "utils.hpp"
#include <map>

namespace modular_aes {
    template<typename Result, typename Query>
    class Oracle {
    public:
        virtual Result encrypt(const Query&) = 0;
        virtual Result decrypt(const Query&) = 0;
    };

    class AESOracle : public Oracle<block_t, block_t> {
        ModularAES aes_;
    public:
        AESOracle(aes_key_t key) : aes_(key) {}
    
        block_t encrypt(const block_t& input) override {
            auto state = input;
            return aes_.encrypt(state, 5);
        }
    
        block_t decrypt(const block_t& input) override {
            auto state = input;
            return aes_.decrypt(state, 5);
        }
    };
    
    class RandomOracle : public Oracle<block_t, block_t> {
        ModularAES aes_ = ModularAES(random_key(NK_128));
        size_t REPS = 3;
    public:
        RandomOracle() {}

        block_t encrypt(const block_t& input) override {
            auto state = input;
            for (size_t i = 0; i < REPS; ++i) {
                state = aes_.encrypt(state);
            }
            return state;
        }
    
        block_t decrypt(const block_t& input) override {
            auto state = input;
            for (size_t i = 0; i < REPS; ++i) {
                state = aes_.decrypt(state);
            }
            return state;
        }
    };
}