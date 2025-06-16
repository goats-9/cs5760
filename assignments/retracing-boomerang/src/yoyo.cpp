#include <cassert>
#include <iostream>
#include "yoyo.hpp"

namespace modular_aes {
    void simple_swap(mzed_t *a, mzed_t *b) {
        // Check if a and b are equal
        mzed_t *c = mzed_add(NULL, a, b);
        assert(!mzed_is_zero(c));
        mzed_free(c);
        for (rci_t col = 0; col < a->ncols; ++col) {
            bool ok = false;
            for (rci_t j = 0; j < a->nrows; ++j) {
                auto wa = mzed_read_elem(a, j, col);
                auto wb = mzed_read_elem(b, j, col);
                if (wa != wb) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                continue;
            }
            for (rci_t j = 0; j < a->nrows; ++j) {
                auto wa = mzed_read_elem(a, j, col);
                auto wb = mzed_read_elem(b, j, col);
                mzed_write_elem(a, j, col, wb);
                mzed_write_elem(b, j, col, wa);
            }
            return;
        }
    }

    bool yoyo_distinguisher_5rd(Oracle<mzed_t *, mzed_t *>& oracle, mzed_t *x0, mzed_t *x1, int _cnt1, int _cnt2) {
        int cnt1 = 0, cnt2 = 0, wrong_pair = 0;
        mzed_t *p0, *p1;
        p0 = mzed_init(gf, NR, NC);
        p1 = mzed_init(gf, NR, NC);
        while (_cnt1 == -1 || cnt1 < _cnt1) {
            cnt1++;
            mzed_custom_randomize(p0);
            mzed_copy(p1, p0);
            for (rci_t j = 0; j < p0->nrows; j++) {
                while (mzed_read_elem(p1, j, 0) == mzed_read_elem(p0, j, 0)) {
                    mzed_write_elem(p1, j, 0, mzed_random_polynomial(gf));
                }
            }
            mzed_copy(x0, p0);
            mzed_copy(x1, p1);
            cnt2 = 0, wrong_pair = 0;
            while (cnt2 < _cnt2 && !wrong_pair) {
                cnt2++;
                shift_rows_(p0, {}, false);
                shift_rows_(p1, {}, false);
                oracle.encrypt(p0);
                oracle.encrypt(p1);
                shift_rows_(p0, {}, false);
                shift_rows_(p1, {}, false);
                simple_swap(p0, p1);
                shift_rows_(p0, {}, true);
                shift_rows_(p1, {}, true);
                oracle.decrypt(p0);
                oracle.decrypt(p1);
                shift_rows_(p0, {}, true);
                shift_rows_(p1, {}, true);
                for (size_t i = 0; i < NC; ++i) {
                    int cnt = 0;
                    for (size_t j = 0; j < NR; ++j) {
                        cnt += mzed_read_elem(p0, j, i) == mzed_read_elem(p1, j, i);
                    }
                    if (cnt >= 2) {
                        wrong_pair = 1;
                        break;
                    }
                }
                simple_swap(p0, p1);
            }
            std::cout << "cnt1 = " << cnt1 << ", cnt2 = " << cnt2 << ", wrong_pair = " << wrong_pair << std::endl;
            if (!wrong_pair) {
                shift_rows_(x0, {}, false);
                shift_rows_(x1, {}, false);
                return true;
            }
        }
        return false;
    }
}
