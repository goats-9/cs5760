#pragma once

#include <cassert>
#include "aes.hpp"
#include "oracle.hpp"

namespace boomerang {
    void simple_swap(block_t&, block_t&);
    bool yoyo_distinguisher_5rd(Oracle<block_t, block_t, aes_key_t>&, size_t, block_t&, block_t&);
}