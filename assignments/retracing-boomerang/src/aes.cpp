#include "aes.hpp"

namespace boomerang {
    block_t AES::add_round_key(block_t state, block_t subkey) {
        return gadd(state, subkey);
    };

    block_t AES::sub_bytes(block_t state, bool inv) {
        auto& s = inv ? Si : S;
        for (auto &w : state) {
            for (auto &b : w) {
                b = s[b];
            }
        }
        return state;
    };

    block_t AES::mix_columns(block_t state, bool inv) {
        return gmul(inv ? MCi : MC, state);
    };

    std::vector<block_t> AES::key_expansion(aes_key_t key) {
        size_t NK = key.size();
        size_t rounds = NK + 6;
        std::vector<block_t> keys(rounds + 1);
        auto sub_word = [&] (word_t w) {
            for (auto &ww : w) {
                ww = S[ww];
            }
            return w;
        };
        auto rot_word = [&] (word_t w) {
            std::rotate(w.begin(), w.begin() + 1, w.end());
            return w;
        };
        for (size_t i = NK; i < 4 * (rounds + 1); ++i) {
            word_t temp = key[i - 1];
            if (i % NK == 0) {
                temp = sub_word(rot_word(temp));
                temp[0] ^= Rcon[i / NK - 1];
            } else if (NK > 6 && i % NK == 4) {
                temp = sub_word(temp);
            }
            key.push_back(gadd(key[i - NK], temp));
        }
        for (size_t i = 0; i <= rounds; ++i) {
            for (int j = 0; j < 4; ++j) {
                for (int k = 0; k < 4; ++k) {
                    keys[i][k][j] = key[4 * i + j][k];
                }
            }
        }
        return keys;
    };

    AES::AES(size_t key_length) {
        assert(key_length == AES_128 || key_length == AES_192 || key_length == AES_256);
        keylen = key_length;
        max_rounds = keylen + 6;
    }

    block_t AES::encrypt(const aes_key_t key, const block_t input, size_t num_rounds) {
        assert(key.size() == keylen);
        if (num_rounds == 0) {
            num_rounds = max_rounds;
        }
        assert(num_rounds <= max_rounds && num_rounds > 0);
        auto subkeys = key_expansion(key);
        block_t state = add_round_key(input, subkeys[0]);
        for (size_t i = 1; i < num_rounds; ++i) {
            state = sub_bytes(state);
            state = shift_rows(state);
            state = mix_columns(state);
            state = add_round_key(state, subkeys[i]);
        }
        state = sub_bytes(state);
        state = shift_rows(state);
        state = add_round_key(state, subkeys[num_rounds]);
        return state;
    }

    block_t AES::decrypt(const aes_key_t key, const block_t input, size_t num_rounds) {
        assert(key.size() == keylen);
        if (num_rounds == 0) {
            num_rounds = max_rounds;
        }
        assert(num_rounds <= max_rounds && num_rounds > 0);
        auto subkeys = key_expansion(key);
        block_t state = add_round_key(input, subkeys[num_rounds]);
        for (size_t i = num_rounds - 1; i > 0; --i) {
            state = shift_rows(state, true);
            state = sub_bytes(state, true);
            state = add_round_key(state, subkeys[i]);
            state = mix_columns(state, true);
        }
        state = shift_rows(state, true);
        state = sub_bytes(state, true);
        state = add_round_key(state, subkeys[0]);
        return state;
    }
}
