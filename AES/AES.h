#pragma once

#include <stdint.h>
#include <stddef.h>

#define AES128 1
// #define AES192 1
// #define AES256 1

// 无论使用哪种 AES 变体（AES-128、AES-192 或 AES-256），数据块的大小始终为 128 位，即 16 字节，4 x 4 矩阵
#define AES_BLOCKLEN 16

// AES_KEYLEN 密钥长度，单位是字节
// AES_keyExpSize 存储扩展密钥的数组大小，单位为字节。AES_keyExpSize = (Nr + 1) × AES_KEYLEN
#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16 
    #define AES_keyExpSize 176
#endif

typedef struct _AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv);

// 缓冲区大小恰好为 AES_BLOCKLEN 字节；
// 在 ECB 模式下，仅需使用 AES_init_ctx，因为 ECB 不使用初始化向量（IV）。
// 注意：ECB 模式被认为是不安全的。
void AES_ECB_encrypt_buffer(const AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt_buffer(const AES_ctx* ctx, uint8_t* buf);

// 缓冲区大小必须是 AES_BLOCKLEN 的倍数；
// 建议使用 PKCS#7 填充方案进行填充
// 注意：
//   - 您需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在上下文中设置 IV。
//   - 永远不要使用相同的密钥重复使用 IV。
void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);

// 加密和解密使用相同的函数。
// 对于每个数据块，IV（初始化向量）都会递增，并在加密后用作输出的 XOR 补码。
// 建议使用 PKCS#7 填充方案。
// 注意：
//   - 您需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在上下文中设置 IV。
//   - 永远不要使用相同的密钥重复使用 IV。
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
