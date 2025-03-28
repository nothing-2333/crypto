#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "murmurhash.h"

int main (void) {
    uint32_t seed = 0;
    const char *key = "CSSStyleDeclaration"; // // 0xb6d99cf8
    uint32_t hash = murmurhash(key, (uint32_t) strlen(key), seed);
    printf("murmurhash(%s) = %d\n", key, hash);
    return 0;
}