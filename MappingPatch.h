#pragma once
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t protocol;
    uint32_t mode;
    uint32_t interface;
} AimeDiscMapEntry;

static inline int AimePatchClassicListen(uint32_t count,
                                         const AimeDiscMapEntry *source,
                                         AimeDiscMapEntry output[2]) {
    static const AimeDiscMapEntry expected[2] = {
        {4, 3, 2},
        {0x80, 1, 0x80}
    };
    if (count != 2 || !source || !output || memcmp(source, expected, sizeof(expected))) return 0;
    memcpy(output, source, sizeof(expected));
    output[1].mode = 2;
    return 1;
}
