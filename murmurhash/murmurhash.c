#include <stdlib.h>
#include <stdio.h>

#include "murmurhash.h"

// 控制是否启用 htole32
#if MURMURHASH_WANTS_HTOLE32
#define MURMURHASH_HAS_HTOLE32 1
#ifndef htole32
static uint32_t htole32 (uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__  // 编译器的定义和系统的字节序（大端或小端）
  value = (
    ((value & 0xFF000000) >> 24) |
    ((value & 0x00FF0000) >> 8)  |
    ((value & 0x0000FF00) << 8)  |
    ((value & 0x000000FF) << 24)
  );
#endif
  return value;
}
#endif
#endif

uint32_t murmurhash(const char *key, uint32_t len, uint32_t seed) {
    uint32_t c1 = 0xcc9e2d51; // 第一个常量，用于乘法运算
    uint32_t c2 = 0x1b873593; // 第二个常量，用于乘法运算
    uint32_t r1 = 15;         // 第一个循环右移位数
    uint32_t r2 = 13;         // 第二个循环右移位数
    uint32_t m = 5;           // 乘法常量
    uint32_t n = 0xe6546b64;  // 加法常量
    uint32_t h = 0;           // 哈希值
    uint32_t k = 0;           // 临时变量，用于处理每个4字节块
    uint8_t *d = (uint8_t *)key; // 将输入字符串转换为字节数组
    const uint32_t *chunks = NULL; // 指向4字节块的指针
    const uint8_t *tail = NULL;    // 指向剩余字节的指针
    int i = 0;                     // 循环变量
    int l = len / 4;               // 4字节块的数量

    h = seed; // 初始化哈希值为种子值

    // 计算4字节块的起始位置和剩余字节的起始位置
    chunks = (const uint32_t *)(d + l * 4); // 指向最后一个4字节块
    tail = (const uint8_t *)(d + l * 4);    // 指向剩余字节的起始位置

    // 遍历每个4字节块
    for (i = -l; i != 0; ++i) {
        // 获取下一个4字节块
#if MURMURHASH_HAS_HTOLE32
        k = htole32(chunks[i]); // 如果需要字节序转换，则调用htole32函数
#else
        k = chunks[i]; // 如果不需要字节序转换，则直接使用
#endif

        // 对4字节块进行编码
        k *= c1; // 第一次乘法
        k = (k << r1) | (k >> (32 - r1)); // 循环右移r1位
        k *= c2; // 第二次乘法

        // 将编码后的块追加到哈希值中
        h ^= k; // 异或操作
        h = (h << r2) | (h >> (32 - r2)); // 循环右移r2位
        h = h * m + n; // 乘法和加法操作
    }

    k = 0; // 重置临时变量

    // 处理剩余的字节（不足4字节的部分）
    switch (len & 3) { // 根据剩余字节的数量进行处理
        case 3: k ^= (tail[2] << 16); // 如果剩余3字节，处理第3个字节
        case 2: k ^= (tail[1] << 8);  // 如果剩余2字节，处理第2个字节
        case 1:  // 如果剩余1字节，处理第1个字节
            k ^= tail[0]; // 处理第1个字节
            k *= c1; // 同样的乘法和旋转操作
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k; // 将处理后的剩余字节追加到哈希值中
    }

    // 最后的混合操作，确保哈希值的均匀分布
    h ^= len; // 将键值的长度异或到哈希值中
    h ^= (h >> 16); // 右移16位并异或
    h *= 0x85ebca6b; // 乘法操作
    h ^= (h >> 13); // 右移13位并异或
    h *= 0xc2b2ae35; // 再次乘法操作
    h ^= (h >> 16); // 最后一次右移和异或

    return h; // 返回最终的哈希值
}