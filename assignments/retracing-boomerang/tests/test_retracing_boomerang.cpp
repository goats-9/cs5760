#include <cassert>
#include "retracing_boomerang.hpp"

using namespace boomerang;

int main() {
    AESOracle oracle;
    auto key = retracing_boomerang_attack(oracle);
    assert(oracle.check(key));
    return 0;
}
