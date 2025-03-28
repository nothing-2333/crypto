#pragma once

#include <stdint.h>

uint32_t murmurhash(const char* key, uint32_t len, uint32_t seed);
