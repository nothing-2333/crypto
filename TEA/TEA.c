#include "TEA.h"

void tea_encrypt(uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = 0;

    for (uint32_t i = 0; i < 32; i++)
    {
        sum += delta;
        data[0] += ((data[1] << 4) + key[0]) ^ (data[1] + sum) ^ ((data[1] >> 5) + key[1]);
        data[1] += ((data[0] << 4) + key[2]) ^ (data[0] + sum) ^ ((data[0] >> 5) + key[3]);
    }
}

void tea_decrypt(uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32;

    for (uint32_t i = 0; i < 32; i++)
    {
        data[1] -= ((data[0] << 4) + key[2]) ^ (data[0] + sum) ^ ((data[0] >> 5) + key[3]);
        data[0] -= ((data[1] << 4) + key[0]) ^ (data[1] + sum) ^ ((data[1] >> 5) + key[1]);
        sum -= delta;
    }
}