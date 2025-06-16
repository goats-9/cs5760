#pragma once

#include <cassert>
#include "aes.hpp"
#include "oracle.hpp"

namespace modular_aes {
    void simple_swap(mzed_t *, mzed_t *);
    bool yoyo_distinguisher_5rd(Oracle<mzed_t *, mzed_t *>&, mzed_t * = NULL, mzed_t * = NULL, int = 1 << 14, int = 1 << 16);
}