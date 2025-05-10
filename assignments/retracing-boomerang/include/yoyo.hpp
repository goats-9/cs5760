#pragma once

#include <cassert>
#include "aes.hpp"
#include "utils.hpp"

namespace ModularAES {
    void simple_swap(block_t&, block_t&);
    bool yoyo_distinguisher_5rd(AES&, block_t&, block_t&);
}