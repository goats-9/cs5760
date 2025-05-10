#include "aes.hpp"
#include "utils.hpp"
#include "yoyo.hpp"
#include <cassert>
using namespace ModularAES;

void test_yoyo() {
    auto key = random_key(NK_128);
    AES aes(key);
    block_t p0, p1;
    assert(yoyo_distinguisher_5rd(aes, p0, p1));    
}

constexpr int TEST_COUNT = 100;

int main() {
    for (int i = 0; i < TEST_COUNT; ++i) {
        test_yoyo();
    }
    return 0;
}