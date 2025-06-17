#include <iostream>
#include "retracing_boomerang.hpp"

namespace boomerang {
    aes_key_t retracing_boomerang_attack(Oracle<block_t, block_t, aes_key_t>& oracle) {
        const size_t sz = 1 << 7;   // Number of plaintext pairs
        const size_t fsz = 1 << 7;  // Number of friend pairs per plaintext pair
        const size_t tsz = 1 << 3;  // Number of test pairs per plaintext pair
        // Precomputation phase: DDT for input difference 0x01
        std::vector<std::vector<byte_t>> ddt(256);
        for (size_t i = 0; i < 256; ++i) {
            size_t j = i ^ 0x01;
            // Store the first element in the DDT.
            ddt[S[i] ^ S[j]].emplace_back(i);
        }
        aes_key_t key(4);
        // Online phase: Attack each inverse shifted column. In this particular
        // implementation, we generate different plaintext pairs for each
        // column.
        for (size_t c = 0; c < NC; c++) {
            std::unordered_map<size_t, size_t> frq;
            // Generate random plaintext pairs with nonzero difference in the
            // first byte and difference of 0x01 in the second byte of the c-th
            // inverse shifted column.
            block_t p0;
            for (auto &u : p0) {
                u.fill(0);
            }
            auto p1 = p0;
            // Set the difference of the second byte in the c-th inverse shifted
            // column to 0x01.
            p1[1][(c + 1) % NC] = 0x01;
            for (size_t i = 0; i < sz; ++i) {
                p1[0][c] = i + 1;
                std::vector<std::pair<block_t, block_t>> friend_pairs;
                std::vector<std::pair<block_t, block_t>> test_pairs;
                // Generate friend pairs and test pairs
                for (size_t j = 0; j < fsz + tsz; ++j) {
                    // Randomize all except the c-th inverse shifted column
                    auto f0 = p0, f1 = p1;
                    for (size_t ii = 0; ii < NR; ++ii) {
                        for (size_t jj = 0; jj < NC; ++jj) {
                            if ((ii + c) % NC == jj) continue;
                            f0[ii][jj] = random_byte();
                            f1[ii][jj] = f0[ii][jj];
                        }
                    }
                    // Perform the yoyo and store the resulting plaintexts
                    f0 = oracle.encrypt(f0);
                    f1 = oracle.encrypt(f1);
                    shift_rows(f0, true);
                    shift_rows(f1, true);
                    simple_swap(f0, f1);
                    shift_rows(f0);
                    shift_rows(f1);
                    f0 = oracle.decrypt(f0);
                    f1 = oracle.decrypt(f1);
                    if (j < fsz) friend_pairs.emplace_back(f0, f1);
                    else test_pairs.emplace_back(f0, f1);
                }
                for (size_t l = 0; l < NR; l++) {
                    // Assume (p0, p1) satisfies Z[l][c] = 0.
                    std::vector<std::pair<byte_t, byte_t>> k0k1;
                    for (size_t k0 = 0; k0 < 256; ++k0) {
                        // Compute contribution of byte (0, c).
                        auto d = gmul(S[p0[0][c] ^ k0] ^ S[p1[0][c] ^ k0], MC[l][0]);
                        auto e = gmul(d, ginv(MC[l][1]));
                        for (auto k1 : ddt[e]) {
                            k0k1.emplace_back(k0, k1);
                        }
                    }
                    // Now find a friend pair that has a zero difference in the
                    // second or third byte of the column.
                    for (auto &[f0, f1] : friend_pairs) {
                        // Find contribution of the first two candidates.
                        std::vector<std::vector<std::pair<byte_t, byte_t>>> k0k1_hash(256);
                        for (auto [k0, k1] : k0k1) {
                            // Compute contribution from first two key bytes
                            auto d = gmul(S[f0[0][c] ^ k0] ^ S[f1[0][c] ^ k0], MC[l][0]);
                            d ^= gmul(S[f0[1][(c + 1) % NC] ^ k1] ^ S[f1[1][(c + 1) % NC] ^ k1], MC[l][1]);
                            // Store this contribution in the hash table
                            k0k1_hash[d].emplace_back(k0, k1);
                        }
                        if (f0[2][(c + 2) % NC] == f1[2][(c + 2) % NC]) {
                            // Iterate over all possibilities of k3 and find a collision.
                            std::vector<std::tuple<byte_t, byte_t, byte_t>> k0k1k3;
                            for (size_t k3 = 0; k3 < 256; ++k3) {
                                auto d = gmul(S[f0[3][(c + 3) % NC] ^ k3] ^ S[f1[3][(c + 3) % NC] ^ k3], MC[l][3]);
                                for (auto [k0, k1] : k0k1_hash[d]) {
                                    // We have a candidate for the key
                                    k0k1k3.emplace_back(k0, k1, k3);
                                }
                            }
                            // Use test pairs to find k2.
                            for (auto &[t0, t1] : test_pairs) {
                                // Ensure the difference in the second byte is nonzero
                                if (t0[2][(c + 2) % NC] == t1[2][(c + 2) % NC]) continue;
                                // Find contributions of k0k1k3.
                                std::vector<std::vector<std::tuple<byte_t, byte_t, byte_t>>> k0k1k3_hash(256);
                                for (auto [k0, k1, k3] : k0k1k3) {
                                    // Compute contribution from first two key bytes
                                    auto d = gmul(S[t0[0][c] ^ k0] ^ S[t1[0][c] ^ k0], MC[l][0]);
                                    d ^= gmul(S[t0[1][(c + 1) % NC] ^ k1] ^ S[t1[1][(c + 1) % NC] ^ k1], MC[l][1]);
                                    d ^= gmul(S[t0[3][(c + 3) % NC] ^ k3] ^ S[t1[3][(c + 3) % NC] ^ k3], MC[l][3]);
                                    // Store this contribution in the hash table
                                    k0k1k3_hash[d].emplace_back(k0, k1, k3);
                                }
                                // Enumerate the possibilities of k2 and find a collision.
                                for (size_t k2 = 0; k2 < 256; ++k2) {
                                    // Compute contribution of k2.
                                    auto d = gmul(S[t0[2][(c + 2) % NC] ^ k2] ^ S[t1[2][(c + 2) % NC] ^ k2], MC[l][2]);
                                    for (auto [k0, k1, k3] : k0k1k3_hash[d]) {
                                        // We have a candidate for the key
                                        size_t candidate = k0 << 24 | k1 << 16 | k2 << 8 | k3;
                                        frq[candidate]++;
                                    }
                                }
                            }
                        }
                        if (f0[3][(c + 3) % NC] == f1[3][(c + 3) % NC]) {
                            // Iterate over all possibilities of k2 and find a collision.
                            std::vector<std::tuple<byte_t, byte_t, byte_t>> k0k1k2;
                            for (size_t k2 = 0; k2 < 256; ++k2) {
                                auto d = gmul(S[f0[2][(c + 2) % NC] ^ k2] ^ S[f1[2][(c + 2) % NC] ^ k2], MC[l][2]);
                                for (auto [k0, k1] : k0k1_hash[d]) {
                                    // We have a candidate for the key
                                    k0k1k2.emplace_back(k0, k1, k2);
                                }
                            }
                            // Use test pairs to find k2.
                            for (auto &[t0, t1] : test_pairs) {
                                // Ensure the difference in the third byte is nonzero
                                if (t0[3][(c + 3) % NC] == t1[3][(c + 3) % NC]) continue;
                                // Find contributions of k0k1k2.
                                std::vector<std::vector<std::tuple<byte_t, byte_t, byte_t>>> k0k1k2_hash(256);
                                for (auto [k0, k1, k2] : k0k1k2) {
                                    // Compute contribution from first two key bytes
                                    auto d = gmul(S[t0[0][c] ^ k0] ^ S[t1[0][c] ^ k0], MC[l][0]);
                                    d ^= gmul(S[t0[1][(c + 1) % NC] ^ k1] ^ S[t1[1][(c + 1) % NC] ^ k1], MC[l][1]);
                                    d ^= gmul(S[t0[2][(c + 2) % NC] ^ k2] ^ S[t1[2][(c + 2) % NC] ^ k2], MC[l][2]);
                                    // Store this contribution in the hash table
                                    k0k1k2_hash[d].emplace_back(k0, k1, k2);
                                }
                                // Enumerate the possibilities of k3 and find a collision.
                                for (size_t k3 = 0; k3 < 256; ++k3) {
                                    // Compute contribution of k3.
                                    auto d = gmul(S[t0[3][(c + 3) % NC] ^ k3] ^ S[t1[3][(c + 3) % NC] ^ k3], MC[l][3]);
                                    for (auto [k0, k1, k2] : k0k1k2_hash[d]) {
                                        // We have a candidate for the key
                                        size_t candidate = k0 << 24 | k1 << 16 | k2 << 8 | k3;
                                        frq[candidate]++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Finally consider the most frequent candidate as the key.
            if (frq.empty()) continue;
            size_t max_candidate = (*frq.begin()).first;
            for (auto [key, val] : frq) {
                if (val > frq[max_candidate]) {
                    max_candidate = key;
                }
            }
            // Store the key
            for (size_t i = 0; i < NR; ++i) {
                key[i][c] = (max_candidate >> (24 - 8 * i)) & 0xff;
            }
            std::cout << "Max candidate for column " << c << ": " << max_candidate << " with frequency " << frq[max_candidate] << std::endl;
        }
        return key;
    }

    // aes_key_t retracing_boomerang_attack_secret_yoyo(Oracle<block_t, block_t>& oracle) {
    //     // Create a GF(2^8) instance to use for solving the system of equations.
    //     gf2e *gf = gf2e_init(irreducible_polynomials[8][1]);
    //     // Get a pair from the yoyo distinguisher, with changed thresholds
    //     block_t p0, p1, c0, c1;
    //     assert(yoyo_distinguisher_5rd(oracle, p0, p1));
    //     // Generate 2^10 + 10 friend pairs for this initial pair
    //     std::vector<std::pair<block_t, block_t>> friend_pairs;
    //     const size_t sz = 10 + (1 << 10);
    //     while (friend_pairs.size() < sz) {
    //         c0 = oracle.encrypt(p0);
    //         c1 = oracle.encrypt(p1);
    //         c0 = shift_rows_(c0, {}, false);
    //         c1 = shift_rows_(c1, {}, false);
    //         simple_swap(c0, c1);
    //         c0 = shift_rows_(c0, {}, true);
    //         c1 = shift_rows_(c1, {}, true);
    //         p0 = oracle.decrypt(c0);
    //         p1 = oracle.decrypt(c1);
    //         friend_pairs.push_back({p0, p1});
    //         p0 = shift_rows_(p0, {}, true);
    //         p1 = shift_rows_(p1, {}, true);
    //         simple_swap(p0, p1);
    //         p0 = shift_rows_(p0, {}, false);
    //         p1 = shift_rows_(p1, {}, false);
    //     }
    //     // Attack each inverse shifted column
    //     std::vector<mzed_t *> rref(4, mzed_init(gf, sz, 1024));
    //     for (int l = 0; l < 4; l++) {
    //         // Eq. 11 from the paper: mc[l] * w[:,l] = 0, where W is the value
    //         // before MC operation. Notice that W_j = SB(P \oplus k_{-1,
    //         // SR^{-1}(j)}) = x_{P, j}.
    //         for (size_t i = 0; i < sz; i++) {
    //             // Create equation for the i-th friend pair
    //             auto [f0, f1] = friend_pairs[i];
    //             for (int j = 0; j < 4; j++) {
    //                 // Get the j-th byte of the l-th word
    //                 auto m0 = f0[j][l];
    //                 auto m1 = f1[j][l];
    //                 // Attach coefficients
    //                 mzed_add_elem(rref[l], i, 4 * m0 + j, MC[l][j]);
    //                 mzed_add_elem(rref[l], i, 4 * m1 + j, MC[l][j]);
    //             }
    //         }
    //         // Perform gaussian elimination to solve the system
    //         int r = mzed_echelonize(rref[l], 0);
    //         std::cout << "l = " << l << ", rank = " << r << std::endl;
    //     }
    //     gf2e_free(gf);
    //     return {};
    // }
}