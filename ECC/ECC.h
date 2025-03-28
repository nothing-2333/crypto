#pragma once

#include <stdint.h>

/* 曲线选择选项。 */
#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
#ifndef ECC_CURVE
    #define ECC_CURVE secp256r1
#endif

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

#define ECC_BYTES ECC_CURVE


/* ecc_make_key() 函数。
创建公钥/私钥对。

输出：
    p_publicKey  - 将被填充为公钥。
    p_privateKey - 将被填充为私钥。

如果成功生成了密钥对，则返回 1；如果发生错误，则返回 0。
*/
int ecc_make_key(uint8_t p_publicKey[ECC_BYTES+1], uint8_t p_privateKey[ECC_BYTES]);

/* ecdh_shared_secret() 函数。
根据你的私钥和对方的公钥计算共享密钥。
注意：在将 ecdh_shared_secret 的结果用于对称加密或 HMAC 之前，建议对其进行哈希处理。

输入：
    p_publicKey  - 对方的公钥。
    p_privateKey - 你的私钥。

输出：
    p_secret - 将被填充为共享密钥值。

如果成功生成了共享密钥，则返回 1；如果发生错误，则返回 0。
*/
int ecdh_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES]);

/* ecdsa_sign() 函数。
为给定的哈希值生成 ECDSA 签名。

用法：计算你要签名的数据的哈希值（推荐使用 SHA-2），然后将其与你的私钥一起传递给此函数。

输入：
    p_privateKey - 你的私钥。
    p_hash       - 要签名的消息哈希值。

输出：
    p_signature  - 将被填充为签名值。

如果成功生成了签名，则返回 1；如果发生错误，则返回 0。
*/
int ecdsa_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2]);

/* ecdsa_verify() 函数。
验证 ECDSA 签名。

用法：使用与签名者相同的哈希算法计算已签名数据的哈希值，并将其与签名者的公钥和签名值（r 和 s）一起传递给此函数。

输入：
    p_publicKey - 签名者的公钥
    p_hash      - 已签名数据的哈希值。
    p_signature - 签名值。

如果签名有效，则返回 1；如果无效，则返回 0。
*/
int ecdsa_verify(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2]);