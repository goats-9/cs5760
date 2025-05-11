#include "aes.hpp"
#include "oracle.hpp"
#include "utils.hpp"
#include "yoyo.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>
using namespace modular_aes;

void test_yoyo_pass(size_t runs = 10) {
    auto key = random_key(NK_128);
    AESOracle oracle(key);
    block_t p0, p1;
    while (runs--) {
        assert(yoyo_distinguisher_5rd(oracle, p0, p1));    
    }
}

int main() {
    test_yoyo_pass(1);
    return 0;
}