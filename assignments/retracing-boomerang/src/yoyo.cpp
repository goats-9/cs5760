#include <cassert>
#include <cmath>
#include <iostream>
#include "yoyo.hpp"

namespace boomerang {
    void simple_swap(block_t& a, block_t& b) {
        assert(a != b);
        // Generate a mask between 1 and 14 determining which columns are to be
        // swapped.
        for (size_t col = 0; col < NC; ++col) {
            bool ok = false;
            for (size_t j = 0; j < NR; ++j) {
                if (a[j][col] != b[j][col]) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                continue;
            }
            for (size_t j = 0; j < NR; ++j) {
                std::swap(a[j][col], b[j][col]);
            }
            return;
        }
    }

    bool yoyo_distinguisher_5rd(Oracle<block_t, block_t, aes_key_t>& oracle, block_t& x0, block_t& x1) {
        int cnt1 = 0, cnt2 = 0, wrong_pair = 0, datacnt = 0;
        block_t p0, p1, c0, c1;
        while (cnt1 < 16384) {
            cnt1++;
            p0 = random_block(), p1 = p0;
            for (size_t j = 0; j < NR; j++) {
                while (p1[j][0] == p0[j][0]) {
                    p1[j][0] = random_byte();
                }
            }
            x0 = p0, x1 = p1;
            cnt2 = 0, wrong_pair = 0;
            while (cnt2 < 65536 && !wrong_pair) {
                cnt2++;
                datacnt += 2;
                p0 = shift_rows(p0, true);
                p1 = shift_rows(p1, true);
                c0 = oracle.encrypt(p0);
                c1 = oracle.encrypt(p1);
                c0 = shift_rows(c0, true);
                c1 = shift_rows(c1, true);
                simple_swap(c0, c1);
                c0 = shift_rows(c0);
                c1 = shift_rows(c1);
                p0 = oracle.decrypt(c0);
                p1 = oracle.decrypt(c1);
                p0 = shift_rows(p0);
                p1 = shift_rows(p1);
                for (size_t i = 0; i < NC; ++i) {
                    int cnt = 0;
                    for (size_t j = 0; j < NR; ++j) {
                        cnt += p0[j][i] == p1[j][i];
                    }
                    if (cnt >= 2 && cnt < 4) {
                        wrong_pair = 1;
                        break;
                    }
                }
                simple_swap(p0, p1);
            }
            std::cout << "cnt1: " << cnt1 << ", cnt2: " << cnt2 << ", wrong_pair: " << wrong_pair << std::endl;
            if (!wrong_pair) {
                x0 = shift_rows(x0, true);
                x1 = shift_rows(x1, true);
                return true;
            }
        }
        return false;
    }
}
