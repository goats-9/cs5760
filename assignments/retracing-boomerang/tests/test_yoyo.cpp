#include "aes.hpp"
#include "utils.hpp"
#include "yoyo.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>
using namespace ModularAES;

void test_yoyo_pass(size_t runs = 10) {
    auto key = random_key(NK_128);
    AES aes(key);
    std::function<block_t(block_t, bool)> oracle = [&](block_t x, bool enc) {
        if (enc) {
            aes.encrypt(x, x, 5);
        } else {
            aes.decrypt(x, x, 5);
        }
        return x;
    };
    block_t p0, p1;
    while (runs--) {
        assert(yoyo_distinguisher_5rd(oracle, p0, p1));    
    }
}

void test_yoyo_fail(size_t runs = 10) {
    auto key = random_key(NK_128);
    AES aes(key);
    std::function<block_t(block_t, bool)> oracle = [&](block_t x, bool enc) {
        if (enc) {
            for (int i = 1; i < 3; i++) {
                aes.encrypt(x, x);
            }
        } else {
            for (int i = 1; i < 3; i++) {
                aes.decrypt(x, x);
            }
        }
        return x;
    };
    block_t p0, p1;
    while (runs--) {
        assert(!yoyo_distinguisher_5rd(oracle, p0, p1));    
    }
}

int main() {
    test_yoyo_pass(1);
    test_yoyo_fail(1);
    return 0;
}