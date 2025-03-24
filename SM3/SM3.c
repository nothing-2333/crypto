#include <string.h>
#include <stdio.h>

#include "SM3.h"

// 内联函数：从字节数组中按大端模式读取一个 32 位整数
static inline uint32_t GET_ULONG_BE(const uint8_t *b, int i)
{
    return ((uint32_t)b[i] << 24) | ((uint32_t)b[i + 1] << 16) |
           ((uint32_t)b[i + 2] << 8) | ((uint32_t)b[i + 3]);
}

// 内联函数：将一个 32 位整数按大端模式存储到字节数组中
static inline void PUT_ULONG_BE(uint32_t n, uint8_t *b, int i)
{
    b[i] = (uint8_t)(n >> 24);
    b[i + 1] = (uint8_t)(n >> 16);
    b[i + 2] = (uint8_t)(n >> 8);
    b[i + 3] = (uint8_t)n;
}

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


void sm3_starts( sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;

}

static void sm3_process( sm3_context *ctx, uint8_t data[64] )
{
    uint32_t SS1, SS2, TT1, TT2, W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t T[64];
    uint32_t Temp1, Temp2, Temp3, Temp4, Temp5;
    int j;

    // 初始化 T 数组
    for (j = 0; j < 16; j++)
        T[j] = 0x79CC4519;
    for (j = 16; j < 64; j++)
        T[j] = 0x7A879D8A;

    // 从输入数据中读取前 16 个 32 位整数
    W[0] = GET_ULONG_BE(data, 0);
    W[1] = GET_ULONG_BE(data, 4);
    W[2] = GET_ULONG_BE(data, 8);
    W[3] = GET_ULONG_BE(data, 12);
    W[4] = GET_ULONG_BE(data, 16);
    W[5] = GET_ULONG_BE(data, 20);
    W[6] = GET_ULONG_BE(data, 24);
    W[7] = GET_ULONG_BE(data, 28);
    W[8] = GET_ULONG_BE(data, 32);
    W[9] = GET_ULONG_BE(data, 36);
    W[10] = GET_ULONG_BE(data, 40);
    W[11] = GET_ULONG_BE(data, 44);
    W[12] = GET_ULONG_BE(data, 48);
    W[13] = GET_ULONG_BE(data, 52);
    W[14] = GET_ULONG_BE(data, 56);
    W[15] = GET_ULONG_BE(data, 60);

    // 计算 W 数组的扩展值
    for (j = 16; j < 68; j++ )
    {
        Temp1 = W[j - 16] ^ W[j - 9];
        Temp2 = ROTL(W[j - 3], 15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 =  ROTL(W[j - 13], 7 ) ^ W[j - 6];
        W[j] = Temp4 ^ Temp5;
    }

    // 计算 W1 数组的值
    for (j =  0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 初始化 A、B、C、D、E、F、G、H 的值
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

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

    // 将计算结果与 ctx->state 中的值进行异或操作
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

void sm3_update( sm3_context *ctx, uint8_t *input, int ilen )
{
    int fill;
    uint32_t left;

    if ( ilen <= 0 ) return;
        
    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if ( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if ( left && ilen >= fill )
    {
        memcpy( (void*)(ctx->buffer + left), (void*)input, fill );
        sm3_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while ( ilen >= 64 )
    {
        sm3_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if ( ilen > 0 ) memcpy( (void*)(ctx->buffer + left), (void*)input, ilen );
}

// 填充
static const uint8_t sm3_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sm3_finish( sm3_context *ctx, uint8_t output[32] )
{
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = ( ctx->total[0] >> 29 )
           | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm3_update( ctx, (uint8_t *) sm3_padding, padn );
    sm3_update( ctx, msglen, 8 );

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}

void sm3( uint8_t *input, int ilen, uint8_t output[32] )
{
    sm3_context ctx;

    sm3_starts( &ctx );
    sm3_update( &ctx, input, ilen );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

