#include "TEA.h"

void encrypt(uint32_t* v, uint32_t* k)
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = 0;

    for (uint32_t i = 0; i < 32; i++)
    {
        sum += delta;
        v[0] += ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        v[1] += ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    }
}

void decrypt(uint32_t* v, uint32_t* k)
{
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32;

    for (uint32_t i = 0; i < 32; i++)
    {
        v[1] -= ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
        v[0] -= ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        sum -= delta;
    }
}