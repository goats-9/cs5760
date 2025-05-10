#include <cassert>
#include <iostream>
#include "yoyo.hpp"

namespace ModularAES {
    void simple_swap(block_t& a, block_t& b) {
        assert(a != b);
        for (size_t i = 0; i < NC; ++i) {
            bool ok = false;
            for (size_t j = 0; j < NR; ++j) {
                if (a[j][i] != b[j][i]) {
                    ok = true;
                    break;
                }
            }
            if (ok) {
                for (size_t j = 0; j < NR; ++j) {
                    std::swap(a[j][i], b[j][i]);
                }
                return;
            }
        } 
    }

    bool yoyo_distinguisher_5rd(AES& aes, block_t& x0, block_t& x1) {
        int cnt1 = 0, cnt2 = 0, wrong_pair = 0;
        block_t p0, p1, c0, c1;
        int CNT1 = 1 << 14;
        int CNT2 = 1 << 12;
        while (cnt1 < CNT1) {
            cnt1++;
            p0 = random_block(), p1 = p0;
            for (size_t j = 0; j < NC; j++) {
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
                aes.encrypt(p0, c0, 5);
                aes.encrypt(p1, c1, 5);
                c0 = shift_rows_(c0, {}, false);
                c1 = shift_rows_(c1, {}, false);
                simple_swap(c0, c1);
                c0 = shift_rows_(c0, {}, true);
                c1 = shift_rows_(c1, {}, true);
                aes.decrypt(c0, p0, 5);
                aes.decrypt(c1, p1, 5);
                p0 = shift_rows_(p0, {}, true);
                p1 = shift_rows_(p1, {}, true);
                auto p = gadd(p0, p1);
                for (size_t i = 0; i < NC; ++i) {
                    int cnt = 0;
                    for (size_t j = 0; j < NR; ++j) {
                        cnt += !p[j][i];
                    }
                    if (cnt >= 2 && cnt < 4) {
                        wrong_pair = 1;
                        break;
                    }
                }
                simple_swap(p0, p1);
            }
            if (!wrong_pair) {
                x0 = shift_rows_(x0, {}, false);
                x1 = shift_rows_(x1, {}, false);
                return true;
            }
        }
        return false;
    }
}
