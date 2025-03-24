#pragma once

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

typedef struct
{
    int mode;                   /*!< 加密模式（加密/解密） */
    unsigned long sk[32];       /*!< SM4子密钥数组，用于存储扩展后的密钥 */
}
sm4_context;

/**
 * \brief          SM4密钥扩展（128位，加密）
 * \param ctx      SM4上下文，将被初始化
 * \param key      16字节的密钥
 */
void sm4_setkey_enc(sm4_context *ctx, unsigned char key[16]);

/**
 * \brief          SM4密钥扩展（128位，解密）
 * \param ctx      SM4上下文，将被初始化
 * \param key      16字节的密钥
 */
void sm4_setkey_dec(sm4_context *ctx, unsigned char key[16]);

/**
 * \brief          SM4-ECB模式的块加密/解密
 * \param ctx      SM4上下文
 * \param mode     加密模式（SM4_ENCRYPT）或解密模式（SM4_DECRYPT）
 * \param length   输入数据的长度（必须是16的倍数）
 * \param input    输入数据块
 * \param output   输出数据块
 */
void sm4_crypt_ecb(sm4_context *ctx,
                   int mode,
                   int length,
                   unsigned char *input,
                   unsigned char *output);

/**
 * \brief          SM4-CBC模式的缓冲区加密/解密
 * \param ctx      SM4上下文
 * \param mode     加密模式（SM4_ENCRYPT）或解密模式（SM4_DECRYPT）
 * \param length   输入数据的长度（必须是16的倍数）
 * \param iv       初始化向量（使用后会更新）
 * \param input    包含输入数据的缓冲区
 * \param output   包含输出数据的缓冲区
 */
void sm4_crypt_cbc(sm4_context *ctx,
                   int mode,
                   int length,
                   unsigned char iv[16],
                   unsigned char *input,
                   unsigned char *output);