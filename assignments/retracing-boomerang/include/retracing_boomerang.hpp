#pragma once
#include <m4rie/m4rie.h>
#include <m4ri/m4ri.h>
#include "aes.hpp"
#include "oracle.hpp"

namespace modular_aes {
    aes_key_t retracing_boomerang_attack(Oracle<block_t, block_t>&);   
}