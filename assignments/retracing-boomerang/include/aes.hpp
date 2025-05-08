#pragma once

#include "utils.hpp"
#include "constants.hpp"

namespace ModularAES {
    class AES {
    public:
        size_t rounds_;
        aes_key_t key_;
        aes_step_t s_box_, inv_s_box_, mix_columns_, inv_mix_columns_;
        std::vector<block_t> subkeys_;
    // public:
        AES(aes_key_t& key,
            size_t rounds = 10,
            aes_step_t s_box = aes_s_box,
            aes_step_t inv_s_box = inv_aes_s_box, 
            aes_step_t mix_columns = aes_mix_columns,
            aes_step_t inv_mix_columns = inv_aes_mix_columns,
            aes_key_schedule_t key_schedule = aes_schedule
        ) : rounds_(rounds), key_(key), s_box_(s_box), inv_s_box_(inv_s_box),
            mix_columns_(mix_columns), inv_mix_columns_(inv_mix_columns), subkeys_(key_schedule(key, rounds)) {}

        void encrypt(const block_t& input, block_t& output);
        void decrypt(const block_t& input, block_t& output);
    };
}