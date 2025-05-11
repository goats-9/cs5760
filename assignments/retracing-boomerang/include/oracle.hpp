#pragma once
#include "utils.hpp"

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
    
    class RandomAESOracle : public Oracle<block_t, block_t> {
        ModularAES aes_;
    public:
        RandomAESOracle(aes_key_t key) : aes_(key) {}
    
        block_t encrypt(const block_t& input) override { 
            auto state = input;
            for (size_t i = 0; i < 3; ++i) {
                state = aes_.encrypt(state);
            }
            return state;
        }
    
        block_t decrypt(const block_t& input) override {
            auto state = input;
            for (size_t i = 0; i < 3; ++i) {
                state = aes_.decrypt(state);
            }
            return state;
        }
    };
}