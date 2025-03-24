# SM3

## 整体梳理
作为一个消息摘要算法，整个算法的核心思想是，输入的信息64字节为一组都“揉进”`uint32_t state[8]`中，然后在将这个`state` hex 编码。

关键的辅助函数`sm3_update` `sm3_finish`，`sm3_update`负责将输入长度超出64子节的部分，分成64字节为一组进行加密，最后不足64字节不予处理。`sm3_finish`负责处理最后不足64字节的部分，将它们按规则填充到64字节再加密，然后将`state`转化输出。

核心加密函数`sm3_process`，将64字节加密，放到`state`中。

## 特点梳理
### 特点一
`state`初始化常量：
```c
ctx->state[0] = 0x7380166F;
ctx->state[1] = 0x4914B2B9;
ctx->state[2] = 0x172442D7;
ctx->state[3] = 0xDA8A0600;
ctx->state[4] = 0xA96F30BC;
ctx->state[5] = 0x163138AA;
ctx->state[6] = 0xE38DEE4D;
ctx->state[7] = 0xB0FB0E4E;
```
### 特点二
最后的填充：0x80, 0, 0 ... 0, 最后8字节是输入的总长度。
### 特点三
运算：
```c

// 内联函数：逻辑左移
static inline uint32_t SHL(uint32_t x, int n)
{
    return ((x) & 0xFFFFFFFF) << n;
}

// 内联函数：循环左移
static inline uint32_t ROTL(uint32_t x, int n)
{
    return SHL(x, n) | (x >> (32 - n));
}

// 内联函数：P0 操作
static inline uint32_t P0(uint32_t x)
{
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

// 内联函数：P1 操作
static inline uint32_t P1(uint32_t x)
{
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// 内联函数：FF0 操作
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

// 内联函数：FF1 操作
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (x & z) | (y & z);
}

// 内联函数：GG0 操作
static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

// 内联函数：GG1 操作
static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (~x & z);
}
```
### 特点四
`sm3_process`中64轮运算，前16轮与后48轮有一点差别：
```c
// 进行 16 轮的压缩计算
for (j = 0; j < 16; j++)
{
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF0(A, B, C) + D + SS2 + W1[j];
    TT2 = GG0(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
}
```
```c
// 再进行 48 轮的压缩计算
for (j = 16; j < 64; j++)
{
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF1(A, B, C) + D + SS2 + W1[j];
    TT2 = GG1(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
}
```
### 特点五
`sm3_process`中最后通过异或运算将结果放入`state`中：
```c
// 将计算结果与 ctx->state 中的值进行异或操作
ctx->state[0] ^= A;
ctx->state[1] ^= B;
ctx->state[2] ^= C;
ctx->state[3] ^= D;
ctx->state[4] ^= E;
ctx->state[5] ^= F;
ctx->state[6] ^= G;
ctx->state[7] ^= H;
```