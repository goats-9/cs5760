#pragma once

#include "utils.hpp"
#include "constants.hpp"

namespace modular_aes {
    inline aes_step_t add_round_key_ = [](block_t state, block_t subkey, bool dir) {
        (void)dir;
        return gadd(state, subkey);
    };

    inline aes_step_t aes_s_box_ = [](block_t state, block_t subkey, bool dir) {
        (void)subkey;
        auto& s = dir ? S : Si;
        for (auto &w : state) {
            for (auto &b : w) {
                b = s[b];
            }
        }
        return state;
    };

    inline aes_step_t aes_mix_columns_ = [] (block_t state, block_t subkey, bool dir) {
        (void)subkey;
        (void)dir;
        return gmul(dir ? MC : IMC, state);
    };

    inline aes_step_t shift_rows_ = [] (block_t state, block_t subkey, bool dir) {
        (void)subkey;
        for (size_t i = 1; i < NR; ++i) {
            int x = dir ? i : (NR - i);
            std::rotate(state[i].begin(), state[i].begin() + x, state[i].end());
        }
        return state;
    };

    inline auto aes_sub_word = [] (word_t w) {
        for (auto &ww : w) {
            ww = S[ww];
        }
        return w;
    };

    inline auto aes_rot_word = [] (word_t w) {
        std::rotate(w.begin(), w.begin() + 1, w.end());
        return w;
    };

    inline aes_key_schedule_t aes_key_expansion_ = [] (aes_key_t key) {
        int NK = key.size();
        size_t rounds = NK + 6;
        std::vector<block_t> keys(rounds + 1);
        for (size_t i = NK; i < 4 * (rounds + 1); ++i) {
            word_t temp = key[i - 1];
            if (i % NK == 0) {
                temp = aes_sub_word(aes_rot_word(temp));
                temp[0] ^= Rcon[i / NK];
            } else if (NK > 6 && i % NK == 4) {
                temp = aes_sub_word(temp);
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

    class ModularAES {
    public:
        aes_key_t key_;
        aes_step_t s_box_, mix_columns_;
        std::vector<block_t> subkeys_;
    // public:
        ModularAES(aes_key_t key,
            aes_step_t s_box_ = aes_s_box_,
            aes_step_t mix_columns_ = aes_mix_columns_,
            aes_key_schedule_t key_expansion_ = aes_key_expansion_
        ) : key_(key), s_box_(s_box_), mix_columns_(mix_columns_),
            subkeys_(key_expansion_(key)) {}

        block_t encrypt(const block_t, size_t = 0);
        block_t decrypt(const block_t, size_t = 0);
    };
}