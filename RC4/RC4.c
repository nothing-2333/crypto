#include "RC4.h"

static unsigned char S[256];

static inline void swap(unsigned char *a, unsigned char *b)
{
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void init_sbox(const char *key, unsigned length)
{
    // 初始化 S 盒
    for (unsigned int i = 0; i < 256; ++i)
    {
        S[i] = i;
    }

    unsigned char T[256] = { 0 };
    // 根据密钥初始化 T 表
    for (int i = 0; i < 256; ++i)
    {
        T[i] = key[i % length];
    }

    // 打乱 S 盒
    for (int i = 0, j = 0; i < 256; ++i)
    {
        j = (j + S[i] + T[i]) % 256;
        swap(&S[i], &S[j]);
    }
}

void rc4_encrypt(char *data, unsigned int data_length, const char *key, unsigned key_length)
{
    init_sbox(key, key_length);
    unsigned char i = 0, j = 0, k, t;
    for (unsigned int h = 0; h < data_length; ++h)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(&S[i], &S[j]);
        
        t = (S[i] + S[j]) % 256;
        k = S[t];
        data[h] ^= k;
    }
}