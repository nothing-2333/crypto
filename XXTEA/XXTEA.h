#pragma once

#include <stdint.h>

void encrypt(unsigned int n, uint32_t value[2], uint32_t const key[4]);

void decrypt(unsigned int n, uint32_t value[2], uint32_t const key[4]);