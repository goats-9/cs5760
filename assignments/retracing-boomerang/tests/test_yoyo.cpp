#include "aes.hpp"
#include "utils.hpp"
#include "yoyo.hpp"
#include <cassert>
using namespace ModularAES;

void test_yoyo_aes() {
    auto key = random_key();
    AES aes(key, 5);
    block_t p0, p1;
    assert(yoyo_distinguisher_5rd(aes, p0, p1));    
}

constexpr int TEST_COUNT = 1;

int main() {
    for (int i = 0; i < TEST_COUNT; ++i) {
        test_yoyo_aes();
    }
    return 0;
}