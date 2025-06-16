#include "aes.hpp"

namespace modular_aes {
    void ModularAES::encrypt(mzed_t *state, size_t num_rounds) {
        if (num_rounds == 0) {
            num_rounds = subkeys.size() - 1; // Default to full rounds
        }
        assert(num_rounds < subkeys.size() && num_rounds > 0);
        add_round_key_(state, subkeys[0], true);
        for (size_t i = 1; i < num_rounds; ++i) {
            s_box(state, subkeys[i], true);
            shift_rows_(state, subkeys[i], true);
            mix_columns(state, subkeys[i], true);
            add_round_key_(state, subkeys[i], true);
        }
        s_box(state, subkeys[num_rounds], true);
        shift_rows_(state, subkeys[num_rounds], true);
        add_round_key_(state, subkeys[num_rounds], true);
    }

    void ModularAES::decrypt(mzed_t *state, size_t num_rounds) {
        if (num_rounds == 0) {
            num_rounds = subkeys.size() - 1; // Default to full rounds
        }
        assert(num_rounds < subkeys.size() && num_rounds > 0);
        add_round_key_(state, subkeys[num_rounds], false);
        for (size_t i = num_rounds - 1; i; --i) {
            shift_rows_(state, subkeys[i], false);
            s_box(state, subkeys[i], false);
            add_round_key_(state, subkeys[i], false);
            mix_columns(state, subkeys[i], false);
        }
        shift_rows_(state, subkeys[0], false);
        s_box(state, subkeys[0], false);
        return add_round_key_(state, subkeys[0], false);
    }
}
