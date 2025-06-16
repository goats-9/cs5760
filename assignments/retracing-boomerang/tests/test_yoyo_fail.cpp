#include <cassert>
#include <iomanip>
#include <iostream>
#include "oracle.hpp"
#include "yoyo.hpp"

using namespace modular_aes;

int main() {
    RandomOracle oracle;
    mzed_t *p0 = NULL, *p1 = NULL;
    assert(!yoyo_distinguisher_5rd(oracle, p0, p1));
    return 0;
}