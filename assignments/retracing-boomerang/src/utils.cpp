#include "utils.hpp"

namespace modular_aes {
    word mzed_random_polynomial(const gf2e *gf) {
        word poly = 0;
        gnutls_rnd(GNUTLS_RND_RANDOM, &poly, sizeof(poly));
        return poly % ((1ULL << gf->degree) - 1);
    }

    void mzed_custom_randomize(mzed_t *m) {
        for (rci_t i = 0; i < m->nrows; ++i) {
            for (rci_t j = 0; j < m->ncols; ++j) {
                mzed_write_elem(m, i, j, mzed_random_polynomial(m->finite_field));
            }
        }
    }

    mzed_t *mzed_from_vector(const gf2e *gf, std::vector<std::vector<uint8_t>> vec) {
        rci_t nrows = vec.size();
        assert(nrows > 0);
        rci_t ncols = vec[0].size();
        mzed_t *m = mzed_init(gf, nrows, ncols);
        for (rci_t i = 0; i < nrows; ++i) {
            assert(vec[i].size() == ncols);
            for (rci_t j = 0; j < ncols; ++j) {
                mzed_write_elem(m, i, j, vec[i][j] & ((1<<gf->degree) - 1));
            }
        }
        return m;
    }
}
