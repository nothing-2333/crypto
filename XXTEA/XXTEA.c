#include "XXTEA.h"

#include<stdio.h>

void encrypt(unsigned int n, uint32_t value[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    unsigned int num_rounds = 6 + 52 / n;
    uint32_t sum = 0;

    uint32_t y, z = value[n - 1];
    unsigned int p, e;

    do 
    {
        sum += delta;
        e = (sum >> 2) & 3;
        for (p = 0; p < n - 1; ++p)
        {
            y = value[p + 1];
            value[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            z = value[p];
        }
        y = value[0];
        value[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        z = value[n - 1];
    }
    while (--num_rounds);
}

void decrypt(unsigned int n, uint32_t value[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    unsigned int num_rounds = 6 + 52 / n;
    uint32_t sum = num_rounds * delta;

    uint32_t y = value[0], z;
    unsigned int p, e;

    do 
    {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0 ; --p)
        {
            z = value[p - 1];
            value[p] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            y = value[p];
        }
        z = value[n - 1];
        value[0] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        y = value[0];

        sum -= delta;
    }
    while (--num_rounds);
}