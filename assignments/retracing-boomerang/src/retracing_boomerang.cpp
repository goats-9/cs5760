#include <iostream>
#include "retracing_boomerang.hpp"

namespace modular_aes {
    mzed_t *retracing_boomerang_attack(Oracle<mzed_t *, mzed_t *>& oracle) {
        // Precomputation of DDT corresponding to input difference 0x01.
        const size_t sz = 1 << 6;
        const size_t fsz = 1 << 7;
        const size_t tsz = 1 << 4;
        std::vector<std::vector<std::pair<byte, byte>>> ddt(256);
        for (word x = 0; x < 256; ++x) {
            byte y = x ^ 0x01;
            byte z = S[x] ^ S[y];
            ddt[z].emplace_back(x, y);
        }
        mzed_t *key = mzed_init(gf, NR, NC);
        // Attack (inverse-shifted) columns
        for (int c = 0; c < 4; c++) {
            // For each inverse-shifted column, generate the initial pairs and
            // attach their friend pairs, mixture counterparts and test mixture
            // counterparts.
            std::vector<std::pair<mzed_t *, mzed_t *>> plaintext_pairs;
            std::vector<std::vector<std::pair<mzed_t *, mzed_t *>>> friend_pairs, mixture_pairs, test_pairs;
            for (size_t i = 0; i < sz; ++i) {
                mzed_t *p1 = mzed_init(gf, NR, NC);
                mzed_custom_randomize(p1);
                mzed_t *p2 = mzed_copy(NULL, p1);
                // Ensure 0-th byte is different
                while (mzed_read_elem(p1, 0, c) == mzed_read_elem(p2, 0, c)) {
                    mzed_write_elem(p2, 0, c, mzed_random_polynomial(p2->finite_field));
                }
                // Force difference of 1-st byte to be 0x01 for MITM attack.
                mzed_write_elem(p1, 1, (c + 1) % NC, 0x00);
                mzed_write_elem(p2, 1, (c + 1) % NC, 0x01);
                plaintext_pairs.emplace_back(p1, p2);
                // For each plaintext pair, attach 2^7 friend pairs. The friend
                // pairs p1' and p2' must satisfy:
                // 1. p1 + p2 = p1' + p2'.
                // 2. Same set of values in the c-th inverse-shifted column.
                std::vector<std::pair<mzed_t *, mzed_t *>> friends, mixtures, tests;
                for (size_t j = 0; j < fsz + tsz; ++j) {
                    auto f1 = mzed_init(gf, NR, NC);
                    auto f2 = mzed_init(gf, NR, NC);
                    mzed_custom_randomize(f1);
                    mzed_custom_randomize(f2);
                    for (size_t x = 0; x < NR; ++x) {
                        for (size_t y = 0; y < NC; ++y) {
                            if (x == y) continue;
                            auto w1 = mzed_random_polynomial(f1->finite_field);
                            auto w2 = w1 ^ mzed_read_elem(p1, x, y) ^ mzed_read_elem(p2, x, y);
                            mzed_write_elem(f1, x, y, w1);
                            mzed_write_elem(f2, x, y, w2);
                        }
                    }
                    if (j < fsz) friends.emplace_back(f1, f2);
                    auto p3 = mzed_copy(NULL, f1);
                    auto p4 = mzed_copy(NULL, f2);
                    oracle.encrypt(p3);
                    oracle.encrypt(p4);
                    simple_swap(p3, p4);
                    // Decrypt to get p3, p4
                    oracle.decrypt(p3);
                    oracle.decrypt(p4);
                    if (j < fsz) mixtures.emplace_back(p3, p4);
                    else tests.emplace_back(p3, p4);
                }
                friend_pairs.emplace_back(std::move(friends));
                mixture_pairs.emplace_back(std::move(mixtures));
                test_pairs.emplace_back(std::move(tests));
            }
            std::unordered_map<word, int> cnt;    // Number of times this key has occurred.
            for (size_t i = 0; i < sz; ++i) {
                auto [p1, p2] = plaintext_pairs[i];
                auto friends = friend_pairs[i];
                auto mixtures = mixture_pairs[i];
                auto tests = test_pairs[i];
                std::vector<std::pair<byte, byte>> k0k1;  // Guesses for first two key bytes in this column
                // Look at bytes corresponding to the c-th column and assume
                // that the difference in the l-th byte is zero. Concretely,
                // Z[l][c] = 0.
                for (int l = 0; l < 4; l++) {
                    // Iterate over all possible values of 0-th byte in current column.
                    for (word k0 = 0; k0 < 256; ++k0) {
                        // Partially encrypt p1, p2 through SB in byte 0, c to
                        // find the output difference. Account for shift-rows.
                        byte w0 = S[mzed_read_elem(p1, 0, c) ^ k0] ^ S[mzed_read_elem(p2, 0, c) ^ k0];
                        // W is the input to MC. Z[i][j] = MC[i] * W[:, j].
                        // Truncated differential characteristic: Zero diff in three
                        // inverse shifted cols -> zero diff in single shifted col.
                        // Here, we assume Z[l][l + c] = 0.
                        byte wl = gf->mul(gf, gf->mul(gf, mzed_read_elem(MC, l, 0), w0), gf->inv(gf, mzed_read_elem(MC, l, 1)));
                        // Now invert using the DDT to get possible guesses for
                        // k0, k5.
                        for (auto [k1, _] : ddt[wl]) {
                            k0k1.emplace_back(k0, k1);
                        }
                    }
                    for (auto [p3, p4] : mixtures) {
                        // Perform a meet in the middle attack
                        auto x2 = mzed_read_elem(p3, 2, (c + 2) % NC) ^ mzed_read_elem(p4, 2, (c + 2) % NC);
                        auto x3 = mzed_read_elem(p3, 3, (c + 3) % NC) ^ mzed_read_elem(p4, 3, (c + 3) % NC);
                        if (!(x2 ^ x3)) continue;   // Exactly one of these two bytes are equal.
                        // Store k0, k1 by their contribution in a hash table.
                        std::vector<std::vector<std::tuple<byte, byte>>> k0k1_hash(256);
                        for (auto [k0, k1] : k0k1) {
                            // Get contribution of first two bytes.
                            auto d0 = S[mzed_read_elem(p3, 0, c) ^ k0] ^ S[mzed_read_elem(p4, 0, c) ^ k0];
                            auto d1 = S[mzed_read_elem(p3, 1, (c + 1) % NC) ^ k1] ^ S[mzed_read_elem(p4, 1, (c + 1) % NC) ^ k1];
                            auto x = gf->mul(gf, mzed_read_elem(MC, l, 0), d0) ^ gf->mul(gf, mzed_read_elem(MC, l, 1), d1);
                            k0k1_hash[x].emplace_back(k0, k1);
                        }
                        if (!x2) {
                            std::vector<std::tuple<byte, byte, byte>> k0k1k3;
                            // Find a collision with the other byte for all possible values of k2.
                            for (word k3 = 0; k3 < 256; ++k3) {
                                // Get contribution of k3.
                                auto d3 = S[mzed_read_elem(p3, 3, (c + 3) % NC) ^ k3] ^ S[mzed_read_elem(p4, 3, (c + 3) % NC) ^ k3];
                                d3 = gf->mul(gf, mzed_read_elem(MC, l, 3), d3);
                                // Check if there is a collision in the hash table.
                                for (auto [k0, k1] : k0k1_hash[d3]) {
                                    // Store the guess for the key.
                                    k0k1k3.emplace_back(k0, k1, k3);
                                }
                            }
                            // Use test pairs to find k2. There should be a
                            // non-zero difference here.
                            for (auto [q3, q4] : tests) {
                                if (mzed_read_elem(q3, 2, (c + 2) % NC) == mzed_read_elem(q4, 2, (c + 2) % NC)) continue;
                                // Get contribution of k0, k1, k3 and create a hash table for this pair.
                                std::vector<std::vector<std::tuple<byte, byte, byte>>> k0k1k3_hash(256);
                                for (auto [k0, k1, k3] : k0k1k3) {
                                    // Get contribution of bytes 0, 1, 3.
                                    auto d0 = S[mzed_read_elem(q3, 0, c) ^ k0] ^ S[mzed_read_elem(q4, 0, c) ^ k0];
                                    auto d1 = S[mzed_read_elem(q3, 1, (c + 1) % NC) ^ k1] ^ S[mzed_read_elem(q4, 1, (c + 1) % NC) ^ k1];
                                    auto d3 = S[mzed_read_elem(q3, 3, (c + 3) % NC) ^ k3] ^ S[mzed_read_elem(q4, 3, (c + 3) % NC) ^ k3];
                                    auto x = gf->mul(gf, mzed_read_elem(MC, l, 0), d0) ^ gf->mul(gf, mzed_read_elem(MC, l, 1), d1) ^ gf->mul(gf, mzed_read_elem(MC, l, 3), d3);
                                    k0k1k3_hash[x].emplace_back(k0, k1, k3);
                                }
                                // Find a collision by enumerating all possible k2.
                                for (word k2 = 0; k2 < 256; ++k2) {
                                    // Get contribution of k2.
                                    auto d2 = S[mzed_read_elem(q3, 2, (c + 2) % NC) ^ k2] ^ S[mzed_read_elem(q4, 2, (c + 2) % NC) ^ k2];
                                    d2 = gf->mul(gf, mzed_read_elem(MC, l, 2), d2);
                                    // Check if there is a collision in the hash table.
                                    for (auto [k0, k1, k3] : k0k1k3_hash[d2]) {
                                        // Store the guess for the key.
                                        word k = k0 << 24 | k1 << 16 | k2 << 8 | k3;
                                        cnt[k]++;
                                    }
                                }
                            }
                        } else if (mzed_read_elem(p3, 3, (l + 3) % NC) == mzed_read_elem(p4, 3, (l + 3) % NC)) {
                            std::vector<std::tuple<byte, byte, byte>> k0k1k2;
                            // Find a collision with the other byte for all possible values of k2.
                            for (word k2 = 0; k2 < 256; ++k2) {
                                // Get contribution of k2.
                                auto d2 = S[mzed_read_elem(p2, 2, (c + 2) % NC) ^ k2] ^ S[mzed_read_elem(p4, 2, (c + 2) % NC) ^ k2];
                                d2 = gf->mul(gf, mzed_read_elem(MC, l, 2), d2);
                                // Check if there is a collision in the hash table.
                                for (auto [k0, k1] : k0k1_hash[d2]) {
                                    // Store the guess for the key.
                                    k0k1k2.emplace_back(k0, k1, k2);
                                }
                            }
                            // Use test pairs to find k3. There should be a
                            // non-zero difference here.
                            for (auto [q3, q4] : tests) {
                                if (mzed_read_elem(q3, 3, (c + 3) % NC) == mzed_read_elem(q4, 3, (c + 3) % NC)) continue;
                                // Get contribution of k0, k1, k2 and create a hash table for this pair.
                                std::vector<std::vector<std::tuple<byte, byte, byte>>> k0k1k2_hash(256);
                                for (auto [k0, k1, k2] : k0k1k2) {
                                    // Get contribution of bytes 0, 1, 2.
                                    auto d0 = S[mzed_read_elem(q3, 0, c) ^ k0] ^ S[mzed_read_elem(q4, 0, c) ^ k0];
                                    auto d1 = S[mzed_read_elem(q3, 1, (c + 1) % NC) ^ k1] ^ S[mzed_read_elem(q4, 1, (c + 1) % NC) ^ k1];
                                    auto d2 = S[mzed_read_elem(q3, 2, (c + 2) % NC) ^ k2] ^ S[mzed_read_elem(q4, 2, (c + 2) % NC) ^ k2];
                                    auto x = gf->mul(gf, mzed_read_elem(MC, l, 0), d0) ^ gf->mul(gf, mzed_read_elem(MC, l, 1), d1) ^ gf->mul(gf, mzed_read_elem(MC, l, 2), d2);
                                    k0k1k2_hash[x].emplace_back(k0, k1, k2);
                                }
                                // Find a collision by enumerating all possible k3.
                                for (word k3 = 0; k3 < 256; ++k3) {
                                    // Get contribution of k3.
                                    auto d3 = S[mzed_read_elem(q3, 3, (c + 3) % NC) ^ k3] ^ S[mzed_read_elem(q4, 3, (c + 3) % NC) ^ k3];
                                    d3 = gf->mul(gf, mzed_read_elem(MC, l, 3), d3);
                                    // Check if there is a collision in the hash table.
                                    for (auto [k0, k1, k2] : k0k1k2_hash[d3]) {
                                        // Store the guess for the key.
                                        word k = k0 << 24 | k1 << 16 | k2 << 8 | k3;
                                        cnt[k]++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Consider the key with max count.
            word k = 0;
            for (auto [candidate, count] : cnt) {
                if (count > cnt[k]) {
                    k = candidate;
                }
            }
            // Store the key in the corresponding column.
            for (int i = 0; i < 4; ++i) {
                mzed_write_elem(key, i, c, (k >> (24 - i * 8)) & 0xFF);
            }
        }
        mzed_print(key);
        return key;
    }
}