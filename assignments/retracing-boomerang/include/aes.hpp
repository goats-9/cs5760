#pragma once

#include <cassert>
#include <iostream>
#include "constants.hpp"

namespace modular_aes {
    inline aes_step_t add_round_key_ = [] (mzed_t *state, mzed_t *subkey, bool dir) {
        (void)dir;
        mzed_add(state, state, subkey);
    };

    inline aes_step_t s_box_ = [] (mzed_t *state, mzed_t *subkey, bool dir) {
        (void)subkey;
        auto& s = dir ? S : Si;
        for (rci_t i = 0; i < state->nrows; ++i) {
            for (rci_t j = 0; j < state->ncols; ++j) {
                word w = mzed_read_elem(state, i, j);
                mzed_write_elem(state, i, j, s[w]);
            }
        }
    };

    inline aes_step_t mix_columns_ = [] (mzed_t *state, mzed_t *subkey, bool dir) {
        (void)subkey;
        (void)dir;
        assert(state->nrows == NR && state->ncols == NC);
        mzed_mul(state, dir ? MC : MCi, state);
    };

    inline aes_step_t shift_rows_ = [] (mzed_t *state, mzed_t *subkey, bool dir) {
        (void)subkey;
        rci_t nr = state->nrows, nc = state->ncols;
        mzed_t *tmp = mzed_init(gf, nr, nc);
        int x = dir ? 1 : -1;
        for (rci_t i = 0; i < nr; ++i) {
            for (rci_t j = 0; j < nc; ++j) {
                rci_t jj = (j + i * x) % nc;
                if (jj < 0) jj += nc; // Ensure jj is non-negative
                word w = mzed_read_elem(state, i, jj);
                mzed_write_elem(tmp, i, j, w);
            }
        }
        state = mzed_copy(state, tmp);
        mzed_free(tmp);
    };

    inline aes_key_schedule_t key_expansion_ = [] (mzed_t *key) {
        size_t nk = key->ncols;
        // Validate key size
        assert(nk == NK_128 || nk == NK_192 || nk == NK_256); // Valid key sizes for AES
        assert(key->nrows == NR);
        // Compute number of AES rounds
        size_t rounds = nk + 6;
        // Initialize keywords for computing the key schedule
        mzed_t *keywords = mzed_init(gf, NC * (rounds + 1), NR);
        // Copy the key into the first part of the keywords
        for (size_t i = 0; i < nk; ++i) {
            for (size_t j = 0; j < NR; ++j) {
                mzed_write_elem(keywords, i, j, mzed_read_elem(key, j, i));
            }
        }
        // Helper routine to rotate a word
        auto rot_word = [&] (mzed_t *w) {
            mzed_t *tmp = mzed_init(gf, 1, NR);
            for (size_t i = 0; i < NR; ++i) {
                mzed_write_elem(tmp, 0, i, mzed_read_elem(w, 0, (i + 1) % NR));
            }
            mzed_copy(w, tmp);
            mzed_free(tmp);
        };
        // Now perform the key schedule
        mzed_t *temp = mzed_init(gf, 1, NR);
        for (size_t i = nk; i < NC * (rounds + 1); ++i) {
            mzed_copy_row(temp, 0, keywords, i - 1);
            if (i % nk == 0) {
                rot_word(temp);
                s_box_(temp, NULL, true);
                mzed_write_elem(temp, 0, 0,
                    mzed_read_elem(temp, 0, 0) ^ Rcon[i / nk - 1]);
            } else if (nk > 6 && i % nk == 4) {
                s_box_(temp, NULL, true);
            }
            mzed_add_row(temp, 0, keywords, i - nk, 0);
            mzed_copy_row(keywords, i, temp, 0);
        }
        mzed_free(temp);
        std::vector<mzed_t *> keys(rounds + 1, mzed_init(gf, NR, NC));
        // Now extract the keys from the keywords
        for (size_t i = 0; i <= rounds; ++i) {
            for (int j = 0; j < 4; ++j) {
                for (int k = 0; k < 4; ++k) {
                    mzed_write_elem(keys[i], k, j,
                        mzed_read_elem(keywords, 4 * i + j, k));
                }
            }
        }
        return keys;
    };


    class ModularAES {
        mzed_t *key;
        aes_step_t s_box, mix_columns;
        std::vector<mzed_t *> subkeys;
    public:
        ModularAES(mzed_t *key = NULL,
            aes_step_t s_box = s_box_,
            aes_step_t mix_columns = mix_columns_,
            aes_key_schedule_t key_expansion = key_expansion_
        ) : key(key), s_box(s_box_), mix_columns(mix_columns_) {
            if (!key) {
                key = mzed_init(gf, NR, NC);
                mzed_custom_randomize(key);
            }
            subkeys = key_expansion(key);
        }

        void encrypt(mzed_t *, size_t = 0);
        void decrypt(mzed_t *, size_t = 0);
    };
}