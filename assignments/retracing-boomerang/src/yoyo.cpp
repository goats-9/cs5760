#include <cassert>
#include <iostream>
#include "yoyo.hpp"

namespace modular_aes {
    void simple_swap(block_t& a, block_t& b) {
        assert(a != b);
        for (size_t col = 0; col < NC; ++col) {
            // Check if the columns are unequal
            bool ok = false;
            for (size_t j = 0; j < NR; ++j) {
                if (a[j][col] != b[j][col]) {
                    ok = true;
                    break;
                }
            }
            if (ok) {
                for (size_t j = 0; j < NR; ++j) {
                    std::swap(a[j][col], b[j][col]);
                }
                return;
            }
        }
    }

    bool yoyo_distinguisher_5rd(Oracle<block_t, block_t>& oracle, block_t& x0, block_t& x1) {
        int cnt1 = 0, cnt2 = 0, wrong_pair = 0, mxcnt = 0;
        block_t p0, p1, c0, c1;
        int CNT1 = 1 << 14;
        int CNT2 = 1 << 15;
        while (cnt1 < CNT1) {
            cnt1++;
            p0 = random_block(), p1 = p0;
            for (size_t j = 0; j < 2; j++) {
                while (p1[j][0] == p0[j][0]) {
                    p1[j][0] = random_byte();
                }
            }
            x0 = p0, x1 = p1;
            cnt2 = 0, wrong_pair = 0;
            while (cnt2 < CNT2 && !wrong_pair) {
                cnt2++;
                p0 = shift_rows_(p0, {}, false);
                p1 = shift_rows_(p1, {}, false);
                c0 = oracle.encrypt(p0);
                c1 = oracle.encrypt(p1);
                c0 = shift_rows_(c0, {}, false);
                c1 = shift_rows_(c1, {}, false);
                simple_swap(c0, c1);
                c0 = shift_rows_(c0, {}, true);
                c1 = shift_rows_(c1, {}, true);
                p0 = oracle.decrypt(c0);
                p1 = oracle.decrypt(c1);
                p0 = shift_rows_(p0, {}, true);
                p1 = shift_rows_(p1, {}, true);
                for (size_t i = 0; i < NC; ++i) {
                    int cnt = 0;
                    for (size_t j = 0; j < NR; ++j) {
                        cnt += p0[j][i] == p1[j][i];
                    }
                    if (cnt >= 2 && cnt < 4) {
                        if (mxcnt < cnt2) {
                            std::cout << cnt1 << ' ' << cnt2 << ' ' << std::endl;
                            mxcnt = cnt2;
                        }
                        wrong_pair = 1;
                        break;
                    }
                }
                simple_swap(p0, p1);
            }
            if (!wrong_pair) {
                std::cout << cnt1 << ' ' << cnt2 << ' ' << std::endl;
                return true;
            }
        }
        return false;
    }
}
