#pragma once

#include <stdint.h>

void tea_encrypt(uint32_t data[2], uint32_t const key[4]);

void tea_decrypt(uint32_t data[2], uint32_t const key[4]);