#include "oracle.hpp"
#include "yoyo.hpp"

using namespace boomerang;

int main() {
    AESOracle oracle;
    block_t p0, p1;
    assert(yoyo_distinguisher_5rd(oracle, p0, p1));    
    return 0;
}