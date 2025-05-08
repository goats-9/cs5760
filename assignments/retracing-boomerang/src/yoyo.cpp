#include <cassert>
#include <iostream>
#include "yoyo.hpp"

namespace ModularAES {
    inline void simple_swap(block_t& a, block_t& b) {
        assert(a != b);
        for (int i = 0; i < NC; ++i) {
            bool ok = false;
            for (int j = 0; j < NR; ++j) {
                if (a[j][i] != b[j][i]) {
                    ok = true;
                    break;
                }
            }
            if (ok) {
                for (int j = 0; j < NR; ++j) {
                    std::swap(a[j][i], b[j][i]);
                }
                return;
            }
        } 
    }

    bool yoyo_distinguisher_5rd(AES& aes, block_t& x0, block_t& x1) {
        int cnt1 = 0, cnt2 = 0, wrong_pair = 0;
        int CNT1 = 1 << 14;
        int CNT2 = 1 << 16;
        block_t p0, p1, c0, c1;
        while (cnt1 < CNT1) {
            cnt1++;
            p0 = random_block(), p1 = p0;
            for (int j = 0; j < NR; j++) {
                while (p1[j][0] == p0[j][0]) {
                    p1[j][0] = random_byte();
                }
            }
            x0 = p0, x1 = p1;
            cnt2 = 0, wrong_pair = 0;
            while (cnt2 < CNT2 && !wrong_pair) {
                cnt2++;
                shift_rows_(p0, true);
                shift_rows_(p1, true);
                aes.encrypt(p0, c0);
                aes.encrypt(p1, c1);
                shift_rows_(c0, true);
                shift_rows_(c1, true);
                simple_swap(c0, c1);
                shift_rows_(c0, false);
                shift_rows_(c1, false);
                aes.decrypt(c0, p0);
                aes.decrypt(c1, p1);
                shift_rows_(p0, false);
                shift_rows_(p1, false);
                auto p = gadd(p0, p1);
                for (int i = 0; i < NC; ++i) {
                    int cnt = 0;
                    for (int j = 0; j < NR; ++j) {
                        cnt += !p[j][i];
                    }
                    if (cnt >= 2 && cnt < 4) {
                        std::cout << cnt1 << " " << cnt2 << std::endl;
                        wrong_pair = 1;
                        break;
                    }
                }
                simple_swap(p0, p1);
            }
            if (!wrong_pair) {
                auto q0 = x0, q1 = x1;
                q0 = gadd(q0, aes.subkeys_[0]);
                q1 = gadd(q1, aes.subkeys_[0]);
                aes.s_box_(q0, aes.subkeys_[1]);
                aes.s_box_(q1, aes.subkeys_[1]);
                aes.mix_columns_(q0, aes.subkeys_[1]);
                aes.mix_columns_(q1, aes.subkeys_[1]);
                q0 = gadd(q0, aes.subkeys_[1]);
                q1 = gadd(q1, aes.subkeys_[1]);
                shift_rows_(q0, false);
                shift_rows_(q1, false);
                auto q = gadd(q0, q1);
                for (auto &v : q0) {
                    for (auto &b : v) {
                        std::cout << (int)b << " ";
                    }
                    std::cout << std::endl;
                }
                std::cout << std::endl;
                for (auto &v : q1) {
                    for (auto &b : v) {
                        std::cout << (int)b << " ";
                    }
                    std::cout << std::endl;
                }
                int cq = 0;
                for (int i = 0; i < NC; ++i) {
                    int cw = 0;
                    for (int j = 0; j < NR; ++j) {
                        cw += !q[j][i];
                    }
                    cq += cw == NR;
                }
                std::cout << "cnt1: " << cnt1 << ", cnt2: " << cnt2 << ", cq: " << cq << std::endl;
                assert(cq == 2);
                return true;
            }
        }
        return false;
    }
}
