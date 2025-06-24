#include <cassert>
#include "oracle.hpp"
#include "yoyo.hpp"

using namespace boomerang;

int main() {
    RandomOracle oracle;
    block_t p0, p1;
    for (size_t i = 0; i < NC; ++i) {
        assert(!yoyo_distinguisher_5rd(oracle, i, p0, p1));    
    }
    return 0;
}