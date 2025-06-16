#pragma once

#include <m4rie/m4rie.h>
#include <vector>
#include <gnutls/crypto.h>

namespace modular_aes {
    word mzed_random_polynomial(const gf2e *);
    void mzed_custom_randomize(mzed_t *);
    mzed_t *mzed_from_vector(const gf2e *, std::vector<std::vector<uint8_t>> vec);
}