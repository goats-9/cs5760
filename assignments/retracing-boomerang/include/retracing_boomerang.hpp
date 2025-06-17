#pragma once

#include <unordered_map>
#include <m4rie/m4rie.h>
#include <m4ri/m4ri.h>
#include "oracle.hpp"
#include "yoyo.hpp"

namespace boomerang {
    aes_key_t retracing_boomerang_attack(Oracle<block_t, block_t, aes_key_t>&);   
    aes_key_t retracing_boomerang_attack_secret(Oracle<block_t, block_t, aes_key_t>&);
    aes_key_t retracing_boomerang_attack_secret_yoyo(Oracle<block_t, block_t, aes_key_t>&);
}