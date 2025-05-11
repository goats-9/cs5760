#include <cassert>
#include "aes.hpp"

namespace modular_aes {
    block_t ModularAES::encrypt(const block_t input, size_t num_rounds) {
        if (num_rounds == 0) {
            num_rounds = subkeys_.size() - 1;
        }
        num_rounds = std::min(num_rounds, subkeys_.size() - 1);
        block_t state = add_round_key_(input, subkeys_[0], true);
        for (size_t i = 1; i < num_rounds; ++i) {
            state = s_box_(state, subkeys_[i], true);
            state = shift_rows_(state, subkeys_[i], true);
            state = mix_columns_(state, subkeys_[i], true);
            state = add_round_key_(state, subkeys_[i], true);
        }
        state = s_box_(state, subkeys_[num_rounds], true);
        state = shift_rows_(state, subkeys_[num_rounds], true);
        return add_round_key_(state, subkeys_[num_rounds], true);
    }

    block_t ModularAES::decrypt(const block_t input, size_t num_rounds) {
        if (num_rounds == 0) {
            num_rounds = subkeys_.size() - 1;
        }
        num_rounds = std::min(num_rounds, subkeys_.size() - 1);
        block_t state = add_round_key_(input, subkeys_[num_rounds], false);
        for (size_t i = num_rounds - 1; i; --i) {
            state = shift_rows_(state, subkeys_[i], false);
            state = s_box_(state, subkeys_[i], false);
            state = add_round_key_(state, subkeys_[i], false);
            state = mix_columns_(state, subkeys_[i], false);
        }
        state = shift_rows_(state, subkeys_[0], false);
        state = s_box_(state, subkeys_[0], false);
        return add_round_key_(state, subkeys_[0], false);
    }
}
