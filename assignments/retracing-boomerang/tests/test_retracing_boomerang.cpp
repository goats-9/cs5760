#include <cassert>
#include "retracing_boomerang.hpp"
using namespace modular_aes;

void test_retracing_boomerang() {
    auto key = random_key(NK_128);
    AESOracle oracle(key);
    retracing_boomerang_attack(oracle);
}

constexpr int TEST_COUNT = 100;

int main() {
    for (int i = 0; i < TEST_COUNT; ++i) {
        test_retracing_boomerang();
    }
    return 0;
}
