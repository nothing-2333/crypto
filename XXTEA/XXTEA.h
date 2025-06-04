#pragma once

#include <stdint.h>

/**
n: data ​​32位无符号整数（uint32_t）的数量
data: 待加密数据
key: 密钥
*/
void xxtea_encrypt(unsigned int n, uint32_t data[2], uint32_t const key[4]);

void xxtea_decrypt(unsigned int n, uint32_t data[2], uint32_t const key[4]);