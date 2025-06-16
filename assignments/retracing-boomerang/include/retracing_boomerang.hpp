#pragma once

#include <m4rie/m4rie.h>
#include "aes.hpp"
#include "oracle.hpp"
#include "yoyo.hpp"

namespace modular_aes {
    mzed_t *retracing_boomerang_attack(Oracle<mzed_t *, mzed_t *>& oracle);
    // mzed_t *retracing_boomerang_attack_secret(Oracle<mzed_t *, mzed_t *>&);   
    // mzed_t *retracing_boomerang_attack_secret_yoyo(Oracle<mzed_t *, mzed_t *>& oracle);
}