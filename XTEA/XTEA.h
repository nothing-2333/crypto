#include <stdint.h>

void encrypt(unsigned int num_rounds, uint32_t value[2], uint32_t const key[4]);

void decrypt(unsigned int num_rounds, uint32_t value[2], uint32_t const key[4]);