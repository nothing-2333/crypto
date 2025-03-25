#pragma once

#include <stdint.h>

/* 定义为 1 以启用 ECDSA 功能，定义为 0 以禁用。
 */
#define SM2_ECDSA 1

/* 优化设置。定义为 1 以启用优化，定义为 0 以禁用。
ECC_SQUARE_FUNC - 如果启用，这将导致使用特定函数进行标量平方运算，而不是通用的乘法函数。可以提高约 8% 的速度。
*/
#define ECC_SQUARE_FUNC 1

/* 目前仅支持 256 位 SM2 */
#define NUM_ECC_DIGITS 32

typedef struct EccPoint
{
    uint8_t x[NUM_ECC_DIGITS]; // 椭圆曲线点的 x 坐标
    uint8_t y[NUM_ECC_DIGITS]; // 椭圆曲线点的 y 坐标
} EccPoint;

/* ecc_make_key() 函数。
创建一个公钥/私钥对。

您必须使用一个新的不可预测的随机数来生成每个新的密钥对。

输出：
    p_publicKey  - 将被填充为表示公钥的点。
    p_privateKey - 将被填充为私钥。

输入：
    p_random - 用于生成密钥对的随机数。

如果密钥对生成成功，返回 1；如果发生错误，返回 0。如果返回 0，请尝试使用不同的随机数。
*/
int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

/* ecc_valid_public_key() 函数。
判断给定点是否在选定的椭圆曲线上（即是否是一个有效的公钥）。

输入：
    p_publicKey - 要检查的点。

如果给定点有效，返回 1；如果无效，返回 0。
*/
int ecc_valid_public_key(EccPoint *p_publicKey);

/* ecdh_shared_secret() 函数。
根据您的私钥和对方的公钥计算共享密钥。

可选地，您可以提供一个随机乘数以抵抗 DPA 攻击。随机乘数应该每次调用 ecdh_shared_secret() 时都不同。

输出：
    p_secret - 将被填充为共享密钥值。
    
输入：
    p_publicKey  - 对方的公钥。
    p_privateKey - 您的私钥。
    p_random     - 用于抵抗 DPA 攻击的可选随机数。如果不关心 DPA 攻击，请传入 NULL。

如果共享密钥计算成功，返回 1；否则返回 0。

注意：建议您在使用共享密钥进行对称加密或 HMAC 之前对 ecdh_shared_secret 的结果进行哈希处理。
如果不哈希共享密钥，您必须调用 ecc_valid_public_key() 来验证对方的公钥是否有效。
如果不进行此验证，攻击者可能会创建一个公钥，导致您使用共享密钥时泄露私钥信息。
*/
int ecdh_shared_secret(uint8_t p_secret[NUM_ECC_DIGITS], EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

#if SM2_ECDSA
/* ecdsa_sign() 函数。
为给定的哈希值生成 ECDSA 签名。

使用方法：计算您要签名的数据的哈希值（推荐使用 SHA-2），并将其与您的私钥和随机数一起传递给此函数。
您必须使用一个新的不可预测的随机数来生成每个新的签名。

输出：
    r, s - 将被填充为签名值。

输入：
    p_privateKey - 您的私钥。
    p_random     - 用于生成签名的随机数。
    p_hash       - 要签名的消息哈希值。

如果签名生成成功，返回 1；如果发生错误，返回 0。如果返回 0，请尝试使用不同的随机数。
*/
int ecdsa_sign(uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS], uint8_t p_privateKey[NUM_ECC_DIGITS],
    uint8_t p_random[NUM_ECC_DIGITS], uint8_t p_hash[NUM_ECC_DIGITS]);

/* ecdsa_verify() 函数。
验证 ECDSA 签名。

使用方法：使用与签名者相同的哈希算法计算已签名数据的哈希值，并将其与签名者的公钥和签名值（r 和 s）一起传递给此函数。

输入：
    p_publicKey - 签名者的公钥
    p_hash      - 已签名数据的哈希值。
    r, s        - 签名值。

如果签名有效，返回 1；如果无效，返回 0。
*/
int ecdsa_verify(EccPoint *p_publicKey, uint8_t p_hash[NUM_ECC_DIGITS], uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS]);

#endif /* ECC_ECDSA */

/* ecc_bytes2native() 函数。
将标准八位字节表示的整数转换为本地格式。

输出：
    p_native - 将被填充为本地整数值。

输入：
    p_bytes - 要转换的整数的标准八位字节表示。
*/
void ecc_bytes2native(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS*4]);

/* ecc_native2bytes() 函数。
将本地格式的整数转换为标准八位字节表示。

输出：
    p_bytes - 将被填充为整数的标准八位字节表示。

输入：
    p_native - 要转换的本地整数值。
*/
void ecc_native2bytes(uint8_t p_bytes[NUM_ECC_DIGITS*4], uint8_t p_native[NUM_ECC_DIGITS]);