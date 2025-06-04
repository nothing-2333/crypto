#include "XXTEA.h"

void xxtea_encrypt(unsigned int n, uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    unsigned int num_rounds = 6 + 52 / n;
    uint32_t sum = 0;

    uint32_t y, z = data[n - 1];
    unsigned int p, e;

    do 
    {
        sum += delta;
        e = (sum >> 2) & 3;
        for (p = 0; p < n - 1; ++p)
        {
            y = data[p + 1];
            data[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            z = data[p];
        }
        y = data[0];
        data[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        z = data[n - 1];
    }
    while (--num_rounds);
}

void xxtea_decrypt(unsigned int n, uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    unsigned int num_rounds = 6 + 52 / n;
    uint32_t sum = num_rounds * delta;

    uint32_t y = data[0], z;
    unsigned int p, e;

    do 
    {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0 ; --p)
        {
            z = data[p - 1];
            data[p] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            y = data[p];
        }
        z = data[n - 1];
        data[0] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
        y = data[0];

        sum -= delta;
    }
    while (--num_rounds);
}