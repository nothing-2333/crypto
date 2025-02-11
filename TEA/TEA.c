#include "TEA.h"

void encrypt(uint32_t value[2], uint32_t const key[4])
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = 0;

    for (uint32_t i = 0; i < 32; i++)
    {
        sum += delta;
        value[0] += ((value[1] << 4) + key[0]) ^ (value[1] + sum) ^ ((value[1] >> 5) + key[1]);
        value[1] += ((value[0] << 4) + key[2]) ^ (value[0] + sum) ^ ((value[0] >> 5) + key[3]);
    }
}

void decrypt(uint32_t value[2], uint32_t const key[4])
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32;

    for (uint32_t i = 0; i < 32; i++)
    {
        value[1] -= ((value[0] << 4) + key[2]) ^ (value[0] + sum) ^ ((value[0] >> 5) + key[3]);
        value[0] -= ((value[1] << 4) + key[0]) ^ (value[1] + sum) ^ ((value[1] >> 5) + key[1]);
        sum -= delta;
    }
}