#include "XTEA.h"

void xtea_encrypt(unsigned int num_rounds, uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = 0;

    for (unsigned int i = 0; i < num_rounds; ++i)
    {
        data[0] += (((data[1] << 4) ^ (data[1] >> 5)) + data[1]) ^ (sum + key[sum & 3]);
        sum += delta;
        data[1] += (((data[0] << 4) ^ (data[0] >> 5)) + data[0]) ^ (sum + key[ (sum >> 11) & 3 ]);
    }
}

void xtea_decrypt(unsigned int num_rounds, uint32_t data[2], uint32_t const key[4])
{
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * num_rounds;

    for (unsigned int i = 0; i < num_rounds; ++i)
    {
        data[1] -= (((data[0] << 4) ^ (data[0] >> 5)) + data[0]) ^ (sum + key[ (sum >> 11) & 3 ]);
        sum -= delta;
        data[0] -= (((data[1] << 4) ^ (data[1] >> 5)) + data[1]) ^ (sum + key[sum & 3]);
    }
}