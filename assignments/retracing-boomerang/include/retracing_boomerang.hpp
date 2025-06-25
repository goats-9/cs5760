#pragma once

#include <unordered_map>
#include <m4rie/m4rie.h>
#include <m4ri/m4ri.h>
#include "oracle.hpp"
#include "yoyo.hpp"

namespace boomerang {
    /**
     * @brief Performs the retracing boomerang attack of Dunkelman et. al. on AES.
     * @param oracle The oracle to use for encryption and decryption.
     * @return The recovered AES key.
     */
    aes_key_t retracing_boomerang_attack(Oracle<block_t, block_t, aes_key_t>&);   

    /**
     * @brief Performs the retracing boomerang attack of Dunkelman et. al. on AES with secret S-boxes.
     * @param oracle The oracle to use for encryption and decryption.
     * @return The recovered AES key.
     */
    aes_key_t retracing_boomerang_attack_secret(Oracle<block_t, block_t, aes_key_t>&);

    /**
     *  @brief Performs the retracing boomerang attack of Dunkelman et. al. on AES with secret S-boxes using the yoyo distinguisher of Ronjom et. al.
     *  @param oracle The oracle to use for encryption and decryption.
     *  @return The recovered AES key.
     */
    aes_key_t retracing_boomerang_attack_secret_yoyo(Oracle<block_t, block_t, aes_key_t>&);
}