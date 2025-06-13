#include "aes.hpp"
#include "oracle.hpp"
#include "utils.hpp"
#include "yoyo.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>
using namespace modular_aes;

int main() {
    AESOracle oracle(random_key(NK_128));
    block_t p0, p1;
    assert(yoyo_distinguisher_5rd(oracle, p0, p1));    
    return 0;
}