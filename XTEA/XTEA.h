#pragma once

#include <stdint.h>

/**
num_rounds: 加密轮数
data: 待加密数据
key: 密钥
*/
void xtea_encrypt(unsigned int num_rounds, uint32_t data[2], uint32_t const key[4]);

void xtea_decrypt(unsigned int num_rounds, uint32_t data[2], uint32_t const key[4]);