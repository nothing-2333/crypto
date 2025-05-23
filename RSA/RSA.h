#pragma once

#include <stdint.h>

// RSA key lengths
#define RSA_MAX_MODULUS_BITS                2048                                      // 模数 n 的最大位数为 2048 位
#define RSA_MAX_MODULUS_LEN                 ((RSA_MAX_MODULUS_BITS + 7) / 8)          // 模数 n 的最大字节长度为 256 字节。
#define RSA_MAX_PRIME_BITS                  ((RSA_MAX_MODULUS_BITS + 1) / 2)          // 质因数 p 和 q 的最大位数为 1024 位。
#define RSA_MAX_PRIME_LEN                   ((RSA_MAX_PRIME_BITS + 7) / 8)            // 质因数 p 和 q 的最大字节长度为 128 字节。


// Error codes
#define ERR_WRONG_DATA                      0x1001
#define ERR_WRONG_LEN                       0x1002

typedef uint64_t dbn_t;
typedef uint32_t bn_t;

void generate_rand(uint8_t *block, uint32_t block_len);

typedef struct {
    uint32_t bits;
    uint8_t  modulus[RSA_MAX_MODULUS_LEN];
    uint8_t  exponent[RSA_MAX_MODULUS_LEN];
} rsa_pk_t;

typedef struct {
    uint32_t bits;
    uint8_t  modulus[RSA_MAX_MODULUS_LEN];
    uint8_t  public_exponet[RSA_MAX_MODULUS_LEN];
    uint8_t  exponent[RSA_MAX_MODULUS_LEN];
    uint8_t  prime1[RSA_MAX_PRIME_LEN];
    uint8_t  prime2[RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent1[RSA_MAX_PRIME_LEN];
    uint8_t  prime_exponent2[RSA_MAX_PRIME_LEN];
    uint8_t  coefficient[RSA_MAX_PRIME_LEN];
} rsa_sk_t;

int rsa_public_encrypt (uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_public_decrypt (uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_private_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);
int rsa_private_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_sk_t *sk);
