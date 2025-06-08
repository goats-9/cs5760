#include <cassert>
#include "retracing_boomerang.hpp"
using namespace modular_aes;

void test_retracing_boomerang(size_t runs = 10) {
    auto key = random_key(NK_128);
    AESOracle oracle(key);
    for (size_t _ = 0; _ < runs; ++_) {
        retracing_boomerang_attack(oracle);
    }
}

int main() {
    test_retracing_boomerang(1);
    return 0;
}
