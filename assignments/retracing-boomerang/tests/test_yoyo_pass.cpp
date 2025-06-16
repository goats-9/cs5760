#include <cassert>
#include <iomanip>
#include <iostream>
#include "oracle.hpp"
#include "yoyo.hpp"

using namespace modular_aes;

int main() {
    AESOracle oracle;
    mzed_t *p0, *p1;
    assert(yoyo_distinguisher_5rd(oracle, p0, p1));
    return 0;
}