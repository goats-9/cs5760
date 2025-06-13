#include <iostream>
#include "yoyo.hpp"
#include "retracing_boomerang.hpp"

namespace modular_aes {
    aes_key_t retracing_boomerang_attack(Oracle<block_t, block_t>& oracle) {
        // Create a GF(2^8) instance to use for solving the system of equations.
        gf2e *gf = gf2e_init(irreducible_polynomials[8][1]);
        // Get a pair from the yoyo distinguisher, with changed thresholds
        block_t p0, p1, c0, c1;
        assert(yoyo_distinguisher_5rd(oracle, p0, p1));
        // Generate 2^10 + 10 friend pairs for this initial pair
        std::vector<std::pair<block_t, block_t>> friend_pairs;
        const size_t sz = 10 + (1 << 10);
        while (friend_pairs.size() < sz) {
            c0 = oracle.encrypt(p0);
            c1 = oracle.encrypt(p1);
            c0 = shift_rows_(c0, {}, false);
            c1 = shift_rows_(c1, {}, false);
            simple_swap(c0, c1);
            c0 = shift_rows_(c0, {}, true);
            c1 = shift_rows_(c1, {}, true);
            p0 = oracle.decrypt(c0);
            p1 = oracle.decrypt(c1);
            friend_pairs.push_back({p0, p1});
            p0 = shift_rows_(p0, {}, true);
            p1 = shift_rows_(p1, {}, true);
            simple_swap(p0, p1);
            p0 = shift_rows_(p0, {}, false);
            p1 = shift_rows_(p1, {}, false);
        }
        // Attack each inverse shifted column
        std::vector<mzed_t *> rref(4, mzed_init(gf, sz, 1024));
        for (int l = 0; l < 4; l++) {
            // Eq. 11 from the paper: mc[l] * w[:,l] = 0, where W is the value
            // before MC operation. Notice that W_j = SB(P \oplus k_{-1,
            // SR^{-1}(j)}) = x_{P, j}.
            for (size_t i = 0; i < sz; i++) {
                // Create equation for the i-th friend pair
                auto [f0, f1] = friend_pairs[i];
                for (int j = 0; j < 4; j++) {
                    // Get the j-th byte of the l-th word
                    auto m0 = f0[j][l];
                    auto m1 = f1[j][l];
                    // Attach coefficients
                    mzed_add_elem(rref[l], i, 4 * m0 + j, MC[l][j]);
                    mzed_add_elem(rref[l], i, 4 * m1 + j, MC[l][j]);
                }
            }
            // Perform gaussian elimination to solve the system
            int r = mzed_echelonize(rref[l], 0);
            std::cout << "l = " << l << ", rank = " << r << std::endl;
        }
        gf2e_free(gf);
        return {};
    }
}