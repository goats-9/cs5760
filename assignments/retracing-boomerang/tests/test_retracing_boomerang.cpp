#include <cassert>
#include "retracing_boomerang.hpp"

using namespace modular_aes;

int main() {
    AESOracle oracle;
    retracing_boomerang_attack(oracle);
    return 0;
}
