#include "aes.hpp"

namespace ModularAES {
	void AES::encrypt(const block_t& input, block_t& output) {
		block_t state = gadd(input, subkeys_[0]);
		for (size_t i = 1; i < rounds_; ++i) {
			s_box_(state, subkeys_[i]);
			shift_rows_(state, false);
			mix_columns_(state, subkeys_[i]);
			state = gadd(state, subkeys_[i]);
		}
		s_box_(state, subkeys_[rounds_]);
		shift_rows_(state, false);
		output = gadd(state, subkeys_[rounds_]);
	}

	void AES::decrypt(const block_t& input, block_t& output) {
		block_t state = gadd(input, subkeys_[rounds_]);
		for (size_t i = rounds_ - 1; i; --i) {
			shift_rows_(state, true);
			inv_s_box_(state, subkeys_[i]);
			state = gadd(state, subkeys_[i]);
			inv_mix_columns_(state, subkeys_[i]);
		}
		shift_rows_(state, true);
		inv_s_box_(state, subkeys_[0]);
		output = gadd(state, subkeys_[0]);
	}
}