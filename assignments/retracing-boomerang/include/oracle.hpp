#pragma once

#include <map>
#include "aes.hpp"

namespace modular_aes {
    template<typename Result, typename Query>
    class Oracle {
    public:
        virtual Result encrypt(Query) = 0;
        virtual Result decrypt(Query) = 0;
    };

    class AESOracle : public Oracle<mzed_t *, mzed_t *> {
        ModularAES aes;
    public:
        AESOracle(mzed_t *key = NULL) : aes(key) {}

        mzed_t *encrypt(mzed_t *input) override {
            mzed_t *state = mzed_copy(NULL, input);
            aes.encrypt(state, 5);
            return state;
        }

        mzed_t *decrypt(mzed_t *input) override {
            mzed_t *state = mzed_copy(NULL, input);
            aes.decrypt(state, 5);
            return state;
        }
    };

    class RandomOracle : public Oracle<mzed_t *, mzed_t *> {
        ModularAES aes = ModularAES();
        size_t REPS = 3;
    public:
        RandomOracle() {}

        mzed_t *encrypt(mzed_t *input) override {
            mzed_t *state = mzed_copy(NULL, input);
            for (size_t i = 0; i < REPS; ++i) {
                aes.encrypt(state, 5);
            }
            return state;
        }

        mzed_t *decrypt(mzed_t *input) override {
            mzed_t *state = mzed_copy(NULL, input);
            for (size_t i = 0; i < REPS; ++i) {
                aes.decrypt(state, 5);
            }
            return state;
        }
    };
}