#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ECC.h"

// 辅助函数：打印十六进制数据
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%-12s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main() {
    int ret;
    
    // 初始化变量
    uint8_t alice_public[ECC_BYTES+1] = {0};
    uint8_t alice_private[ECC_BYTES] = {0};
    uint8_t bob_public[ECC_BYTES+1] = {0};
    uint8_t bob_private[ECC_BYTES] = {0};
    uint8_t secret1[ECC_BYTES] = {0};
    uint8_t secret2[ECC_BYTES] = {0};
    
    // 示例哈希值（在真实场景应使用 SHA-256 等哈希算法）
    uint8_t hash[ECC_BYTES];
    memset(hash, 0x01, sizeof(hash)); // 填充测试值
    
    uint8_t signature[ECC_BYTES*2] = {0};
    
    printf("=== ECC 测试 ===\n\n");

    // 测试密钥对生成
    printf("[测试1] 生成密钥对...\n");
    ret = ecc_make_key(alice_public, alice_private);
    if (ret != 1) {
        fprintf(stderr, "错误：Alice 密钥生成失败\n");
        return EXIT_FAILURE;
    }
    ret = ecc_make_key(bob_public, bob_private);
    if (ret != 1) {
        fprintf(stderr, "错误：Bob 密钥生成失败\n");
        return EXIT_FAILURE;
    }
    print_hex("Alice私钥", alice_private, ECC_BYTES);
    print_hex("Alice公钥", alice_public, ECC_BYTES+1);
    print_hex("Bob私钥", bob_private, ECC_BYTES);
    print_hex("Bob公钥", bob_public, ECC_BYTES+1);
    printf("密钥对生成测试通过\n\n");

    // 测试 ECDH 共享密钥
    printf("[测试2] ECDH 共享密钥...\n");
    ret = ecdh_shared_secret(bob_public, alice_private, secret1);
    if (ret != 1) {
        fprintf(stderr, "错误：Alice 共享密钥计算失败\n");
        return EXIT_FAILURE;
    }
    ret = ecdh_shared_secret(alice_public, bob_private, secret2);
    if (ret != 1) {
        fprintf(stderr, "错误：Bob 共享密钥计算失败\n");
        return EXIT_FAILURE;
    }
    print_hex("Alice计算密钥", secret1, ECC_BYTES);
    print_hex("Bob计算密钥", secret2, ECC_BYTES);
    
    if (memcmp(secret1, secret2, ECC_BYTES) != 0) {
        fprintf(stderr, "错误：共享密钥不匹配\n");
        return EXIT_FAILURE;
    }
    printf("ECDH 共享密钥测试通过\n\n");

    // 测试 ECDSA 签名验证
    printf("[测试3] ECDSA 签名验证...\n");
    ret = ecdsa_sign(alice_private, hash, signature);
    if (ret != 1) {
        fprintf(stderr, "错误：签名失败\n");
        return EXIT_FAILURE;
    }
    print_hex("签名", signature, ECC_BYTES*2);
    
    ret = ecdsa_verify(alice_public, hash, signature);
    if (ret != 1) {
        fprintf(stderr, "错误：签名验证失败\n");
        return EXIT_FAILURE;
    }
    printf("有效签名验证成功\n");

    // 测试无效签名检测
    printf("[测试4] 无效签名检测...\n");
    uint8_t bad_signature[ECC_BYTES*2];
    memcpy(bad_signature, signature, sizeof(bad_signature));
    bad_signature[0] ^= 0x55; // 篡改签名
    
    ret = ecdsa_verify(alice_public, hash, bad_signature);
    if (ret != 0) {
        fprintf(stderr, "错误：无效签名被错误接受\n");
        return EXIT_FAILURE;
    }
    printf("无效签名检测成功\n");

    printf("\n所有测试通过！\n");
    return EXIT_SUCCESS;
}