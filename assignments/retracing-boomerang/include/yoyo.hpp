#pragma once

#include <cassert>
#include "aes.hpp"
#include "oracle.hpp"
#include "utils.hpp"

namespace modular_aes {
    void simple_swap(block_t&, block_t&);
    bool yoyo_distinguisher_5rd(Oracle<block_t, block_t>&, block_t&, block_t&, int = 10000, int = 25000);
}