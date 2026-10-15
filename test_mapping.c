#include <assert.h>
#include "MappingPatch.h"

int main(void) {
    AimeDiscMapEntry source[2] = {{4,3,2},{0x80,1,0x80}}, output[2] = {{0}};
    assert(AimePatchClassicListen(2, source, output));
    assert(output[0].protocol == 4 && output[0].mode == 3 && output[0].interface == 2);
    assert(output[1].protocol == 0x80 && output[1].mode == 2 && output[1].interface == 0x80);
    assert(source[1].mode == 1);
    source[1].interface = 2;
    assert(!AimePatchClassicListen(2, source, output));
    assert(!AimePatchClassicListen(1, source, output));
    assert(!AimePatchClassicListen(2, 0, output));
    return 0;
}
