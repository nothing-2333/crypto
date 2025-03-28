#include <string.h>

#include "ECC.h"

#define NUM_ECC_DIGITS (ECC_BYTES/8)    // 定义椭圆曲线数字的位数
#define MAX_TRIES 16                    // 定义在生成私钥时的最大尝试次数

typedef unsigned int uint;

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
    #define SUPPORTS_INT128 1
#else
    #define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
    uint64_t m_low;
    uint64_t m_high;
} uint128_t;
#endif

typedef struct EccPoint
{
    uint64_t x[NUM_ECC_DIGITS];
    uint64_t y[NUM_ECC_DIGITS];
} EccPoint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define Curve_P_16 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFDFFFFFFFF}
#define Curve_P_24 {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_P_32 {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#define Curve_P_48 {0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

#define Curve_B_16 {0xD824993C2CEE5ED3, 0xE87579C11079F43D}
#define Curve_B_24 {0xFEB8DEECC146B9B1ull, 0x0FA7E9AB72243049ull, 0x64210519E59C80E7ull}
#define Curve_B_32 {0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}
#define Curve_B_48 {0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4}

#define Curve_G_16 { \
    {0x0C28607CA52C5B86, 0x161FF7528B899B2D}, \
    {0xC02DA292DDED7A83, 0xCF5AC8395BAFEB13}}

#define Curve_G_24 { \
    {0xF4FF0AFD82FF1012ull, 0x7CBF20EB43A18800ull, 0x188DA80EB03090F6ull}, \
    {0x73F977A11E794811ull, 0x631011ED6B24CDD5ull, 0x07192B95FFC8DA78ull}}
    
#define Curve_G_32 { \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull}}

#define Curve_G_48 { \
    {0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537}, \
    {0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F}}

#define Curve_N_16 {0x75A30D1B9038A115, 0xFFFFFFFE00000000}
#define Curve_N_24 {0x146BC9B1B4D22831ull, 0xFFFFFFFF99DEF836ull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_N_32 {0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull}
#define Curve_N_48 {0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

static uint64_t curve_p[NUM_ECC_DIGITS] = CONCAT(Curve_P_, ECC_CURVE);
static uint64_t curve_b[NUM_ECC_DIGITS] = CONCAT(Curve_B_, ECC_CURVE);
static EccPoint curve_G = CONCAT(Curve_G_, ECC_CURVE);
static uint64_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, ECC_CURVE);

// 根据操作系统类型选择不同的随机数生成方式
#if (defined(_WIN32) || defined(_WIN64))
/* Windows平台 */

#define WIN32_LEAN_AND_MEAN // 减少Windows头文件的包含内容
#include <windows.h> // 包含Windows API头文件
#include <wincrypt.h> // 包含Windows加密API头文件

// 获取随机数的函数
static int getRandomNumber(uint64_t *p_vli)
{
    HCRYPTPROV l_prov; // 加密服务提供者句柄
    // 尝试获取一个用于生成随机数的加密服务提供者
    if(!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        // 如果获取失败，返回0表示失败
        return 0;
    }

    // 使用加密服务提供者生成随机数
    CryptGenRandom(l_prov, ECC_BYTES, (BYTE *)p_vli);
    // 释放加密服务提供者句柄
    CryptReleaseContext(l_prov, 0);
    
    // 返回1表示成功
    return 1;
}

#else /* _WIN32 */

/* 假设在类Unix系统上，使用/dev/urandom或/dev/random获取随机数 */
#include <sys/types.h> // 包含系统类型定义
#include <fcntl.h> // 包含文件控制选项定义
#include <unistd.h> // 包含标准符号常量和类型定义

// 如果系统没有定义O_CLOEXEC，则定义为0
#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif

// 获取随机数的函数
static int getRandomNumber(uint64_t *p_vli)
{
    // 尝试打开/dev/urandom设备获取随机数
    int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(l_fd == -1)
    {
        // 如果/dev/urandom打开失败，尝试打开/dev/random
        l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if(l_fd == -1)
        {
            // 如果/dev/random也打开失败，返回0表示失败
            return 0;
        }
    }
    
    // 将目标指针转换为char指针，用于按字节读取
    char *l_ptr = (char *)p_vli;
    // 计算还需要读取的字节数
    size_t l_left = ECC_BYTES;
    // 循环读取随机数
    while(l_left > 0)
    {
        // 从随机数设备读取数据
        int l_read = read(l_fd, l_ptr, l_left);
        if(l_read <= 0)
        { // 如果读取失败
            // 关闭文件描述符
            close(l_fd);
            // 返回0表示失败
            return 0;
        }
        // 更新还需要读取的字节数和目标指针位置
        l_left -= l_read;
        l_ptr += l_read;
    }
    
    // 关闭文件描述符
    close(l_fd);
    // 返回1表示成功
    return 1;
}

#endif /* _WIN32 */

static void vli_clear(uint64_t *p_vli)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_vli[i] = 0;
    }
}

/* 如果 p_vli == 0，则返回 1，否则返回 0。 */
static int vli_isZero(uint64_t *p_vli)
{
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        if(p_vli[i])
        {
            return 0; // 如果任何一位不为零，则 p_vli 不为零
        }
    }
    return 1; // 如果所有位都为零，则 p_vli 为零
}

/* 如果 p_vli 的第 p_bit 位被设置，则返回非零值。 */
static uint64_t vli_testBit(uint64_t *p_vli, uint p_bit)
{
    // 返回指定位的值（0 或 1）
    return (p_vli[p_bit/64] & ((uint64_t)1 << (p_bit % 64)));
}

/* 计算 p_vli 中的 64 位“数字”的数量。 */
static uint vli_numDigits(uint64_t *p_vli)
{
    int i;
    /* 从末尾开始搜索，直到找到一个非零数字。
       我们反向搜索是因为我们预计大多数数字都不会为零。 */
    for(i = NUM_ECC_DIGITS - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1); // 返回非零数字的数量
}

/* 计算存储 p_vli 所需的位数。 */
static uint vli_numBits(uint64_t *p_vli)
{
    uint i;
    uint64_t l_digit;
    
    uint l_numDigits = vli_numDigits(p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }
    
    return ((l_numDigits - 1) * 64 + i);
}

/* p_dest = p_src. */
static void vli_set(uint64_t *p_dest, uint64_t *p_src)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* 返回 p_left - p_right 的符号。 */
static int vli_cmp(uint64_t *p_left, uint64_t *p_right)
{
    int i;
    for(i = NUM_ECC_DIGITS-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* 计算 p_result = p_in << c，并返回进位信息。可以对原变量进行就地修改（如果 p_result == p_in）。0 < c < 64。 */
static uint64_t vli_lshift(uint64_t *p_result, uint64_t *p_in, uint p_shift)
{
    uint64_t l_carry = 0;
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }
    
    return l_carry;
}

/* 计算 p_vli = p_vli >> 1. */
static void vli_rshift1(uint64_t *p_vli)
{
    uint64_t *l_end = p_vli;
    uint64_t l_carry = 0;
    
    p_vli += NUM_ECC_DIGITS;
    while(p_vli-- > l_end)
    {
        uint64_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 63;
    }
}

/* 计算 p_result = p_left + p_right，并返回借位信息。可以对原变量进行就地修改。 */
static uint64_t vli_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_carry = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* 计算 p_result = p_left - p_right，并返回借位信息。可以对原变量进行就地修改。 */
static uint64_t vli_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_borrow = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

#if SUPPORTS_INT128

/* 计算 p_result = p_left × p_right。 */
static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    
    /* 按顺序计算 p_result 的每一位数字，并保持进位。 */
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<NUM_ECC_DIGITS; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[NUM_ECC_DIGITS*2 - 1] = (uint64_t)r01;
}

/* 计算 p_result = p_left^2. */
static void vli_square(uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 127;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[NUM_ECC_DIGITS*2 - 1] = (uint64_t)r01;
}

#else /* #if SUPPORTS_INT128 */

static uint128_t mul_64_64(uint64_t p_left, uint64_t p_right)
{
    uint128_t l_result;
    
    uint64_t a0 = p_left & 0xffffffffull;
    uint64_t a1 = p_left >> 32;
    uint64_t b0 = p_right & 0xffffffffull;
    uint64_t b1 = p_right >> 32;
    
    uint64_t m0 = a0 * b0;
    uint64_t m1 = a0 * b1;
    uint64_t m2 = a1 * b0;
    uint64_t m3 = a1 * b1;
    
    m2 += (m0 >> 32);
    m2 += m1;
    if(m2 < m1)
    { // overflow
        m3 += 0x100000000ull;
    }
    
    l_result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
    l_result.m_high = m3 + (m2 >> 32);
    
    return l_result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
    uint128_t l_result;
    l_result.m_low = a.m_low + b.m_low;
    l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
    return l_result;
}

static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<NUM_ECC_DIGITS; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_right[k-i]);
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[NUM_ECC_DIGITS*2 - 1] = r01.m_low;
}

static void vli_square(uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint i, k;
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_left[k-i]);
            if(i < k-i)
            {
                r2 += l_product.m_high >> 63;
                l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >> 63);
                l_product.m_low <<= 1;
            }
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[NUM_ECC_DIGITS*2 - 1] = r01.m_low;
}

#endif /* SUPPORTS_INT128 */

/* 计算 p_result = (p_left + p_right) % p_mod。
   假设 p_left < p_mod 且 p_right < p_mod，p_result != p_mod。 */
static void vli_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_carry = vli_add(p_result, p_left, p_right); // 计算 p_left + p_right，返回进位信息
    if(l_carry || vli_cmp(p_result, p_mod) >= 0)
    { /* 如果 p_result > p_mod（即 p_result = p_mod + 余数），则需要减去 p_mod 以得到余数。 */
        vli_sub(p_result, p_result, p_mod); // 从 p_result 中减去 p_mod
    }
}

/* 计算 p_result = (p_left - p_right) % p_mod。
   假设 p_left < p_mod 且 p_right < p_mod，p_result != p_mod。 */
static void vli_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_borrow = vli_sub(p_result, p_left, p_right); // 计算 p_left - p_right，返回借位信息
    if(l_borrow)
    { /* 在这种情况下，p_result == -diff == (最大整数) - diff。
         由于 -x % d == d - x，我们可以通过 p_result + p_mod（允许溢出）来得到正确的结果。 */
        vli_add(p_result, p_result, p_mod); // 将 p_mod 加到 p_result 上
    }
}

#if ECC_CURVE == secp128r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;
    
    vli_set(p_result, p_product);
    
    l_tmp[0] = p_product[2];
    l_tmp[1] = (p_product[3] & 0x1FFFFFFFFull) | (p_product[2] << 33);
    l_carry = vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[2] >> 31) | (p_product[3] << 33);
    l_tmp[1] = (p_product[3] >> 31) | ((p_product[2] & 0xFFFFFFFF80000000ull) << 2);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[2] >> 62) | (p_product[3] << 2);
    l_tmp[1] = (p_product[3] >> 62) | ((p_product[2] & 0xC000000000000000ull) >> 29) | (p_product[3] << 35);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[3] >> 29);
    l_tmp[1] = ((p_product[3] & 0xFFFFFFFFE0000000ull) << 4);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[3] >> 60);
    l_tmp[1] = (p_product[3] & 0xFFFFFFFE00000000ull);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = 0;
    l_tmp[1] = ((p_product[3] & 0xF000000000000000ull) >> 27);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp192r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;
    
    vli_set(p_result, p_product);
    
    vli_set(l_tmp, &p_product[3]);
    l_carry = vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = 0;
    l_tmp[1] = p_product[3];
    l_tmp[2] = p_product[4];
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = l_tmp[1] = p_product[5];
    l_tmp[2] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp256r1

/* 计算 p_result = p_product % curve_p
   参考：http://www.nsa.gov/ia/_files/nist-routines.pdf 
*/

/* 快速模运算 */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS]; // 临时变量，用于存储中间结果
    int l_carry; // 进位标志，用于处理模运算中的进位和借位

    /* t */
    // 将 p_product 的值复制到 p_result
    vli_set(p_result, p_product);

    /* s1 */
    // 初始化 l_tmp 的值
    l_tmp[0] = 0;
    l_tmp[1] = p_product[5] & 0xffffffff00000000ull; // 提取 p_product[5] 的高32位
    l_tmp[2] = p_product[6];
    l_tmp[3] = p_product[7];
    // 将 l_tmp 左移1位，并处理进位
    l_carry = vli_lshift(l_tmp, l_tmp, 1);
    // 将 l_tmp 加到 p_result，并更新进位
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s2 */
    // 更新 l_tmp 的值
    l_tmp[1] = p_product[6] << 32; // 将 p_product[6] 左移32位
    l_tmp[2] = (p_product[6] >> 32) | (p_product[7] << 32); // 组合 p_product[6] 和 p_product[7] 的部分位
    l_tmp[3] = p_product[7] >> 32; // 提取 p_product[7] 的高32位
    // 将 l_tmp 左移1位，并处理进位
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    // 将 l_tmp 加到 p_result，并更新进位
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s3 */
    // 更新 l_tmp 的值
    l_tmp[0] = p_product[4];
    l_tmp[1] = p_product[5] & 0xffffffff; // 提取 p_product[5] 的低32位
    l_tmp[2] = 0;
    l_tmp[3] = p_product[7];
    // 将 l_tmp 加到 p_result，并更新进位
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* s4 */
    // 更新 l_tmp 的值
    l_tmp[0] = (p_product[4] >> 32) | (p_product[5] << 32); // 组合 p_product[4] 和 p_product[5] 的部分位
    l_tmp[1] = (p_product[5] >> 32) | (p_product[6] & 0xffffffff00000000ull); // 组合 p_product[5] 和 p_product[6] 的部分位
    l_tmp[2] = p_product[7];
    l_tmp[3] = (p_product[6] >> 32) | (p_product[4] << 32); // 组合 p_product[6] 和 p_product[4] 的部分位
    // 将 l_tmp 加到 p_result，并更新进位
    l_carry += vli_add(p_result, p_result, l_tmp);

    /* d1 */
    // 更新 l_tmp 的值
    l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32); // 组合 p_product[5] 和 p_product[6] 的部分位
    l_tmp[1] = (p_product[6] >> 32);
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] & 0xffffffff) | (p_product[5] << 32); // 组合 p_product[4] 和 p_product[5] 的部分位
    // 从 p_result 中减去 l_tmp，并更新进位
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* d2 */
    // 更新 l_tmp 的值
    l_tmp[0] = p_product[6];
    l_tmp[1] = p_product[7];
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] >> 32) | (p_product[5] & 0xffffffff00000000ull); // 组合 p_product[4] 和 p_product[5] 的部分位
    // 从 p_result 中减去 l_tmp，并更新进位
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* d3 */
    // 更新 l_tmp 的值
    l_tmp[0] = (p_product[6] >> 32) | (p_product[7] << 32); // 组合 p_product[6] 和 p_product[7] 的部分位
    l_tmp[1] = (p_product[7] >> 32) | (p_product[4] << 32); // 组合 p_product[7] 和 p_product[4] 的部分位
    l_tmp[2] = (p_product[4] >> 32) | (p_product[5] << 32); // 组合 p_product[4] 和 p_product[5] 的部分位
    l_tmp[3] = (p_product[6] << 32);
    // 从 p_result 中减去 l_tmp，并更新进位
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    /* d4 */
    // 更新 l_tmp 的值
    l_tmp[0] = p_product[7];
    l_tmp[1] = p_product[4] & 0xffffffff00000000ull; // 提取 p_product[4] 的高32位
    l_tmp[2] = p_product[5];
    l_tmp[3] = p_product[6] & 0xffffffff00000000ull; // 提取 p_product[6] 的高32位
    // 从 p_result 中减去 l_tmp，并更新进位
    l_carry -= vli_sub(p_result, p_result, l_tmp);

    // 处理最终的进位
    if(l_carry < 0)
    {
        // 如果进位为负，表示 p_result 小于 curve_p，需要加上 curve_p
        do
        {
            l_carry += vli_add(p_result, p_result, curve_p);
        } while(l_carry < 0);
    }
    else
    {
        // 如果进位为正，表示 p_result 大于或等于 curve_p，需要减去 curve_p
        while(l_carry || vli_cmp(curve_p, p_result) != 1)
        {
            l_carry -= vli_sub(p_result, p_result, curve_p);
        }
    }
}

#elif ECC_CURVE == secp384r1

static void omega_mult(uint64_t *p_result, uint64_t *p_right)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    uint64_t l_carry, l_diff;
    
    /* Multiply by (2^128 + 2^96 - 2^32 + 1). */
    vli_set(p_result, p_right); /* 1 */
    l_carry = vli_lshift(l_tmp, p_right, 32);
    p_result[1 + NUM_ECC_DIGITS] = l_carry + vli_add(p_result + 1, p_result + 1, l_tmp); /* 2^96 + 1 */
    p_result[2 + NUM_ECC_DIGITS] = vli_add(p_result + 2, p_result + 2, p_right); /* 2^128 + 2^96 + 1 */
    l_carry += vli_sub(p_result, p_result, l_tmp); /* 2^128 + 2^96 - 2^32 + 1 */
    l_diff = p_result[NUM_ECC_DIGITS] - l_carry;
    if(l_diff > p_result[NUM_ECC_DIGITS])
    { /* Propagate borrow if necessary. */
        uint i;
        for(i = 1 + NUM_ECC_DIGITS; ; ++i)
        {
            --p_result[i];
            if(p_result[i] != (uint64_t)-1)
            {
                break;
            }
        }
    }
    p_result[NUM_ECC_DIGITS] = l_diff;
}

/* Computes p_result = p_product % curve_p
    see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
    section "Curve-Specific Optimizations" */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[2*NUM_ECC_DIGITS];
     
    while(!vli_isZero(p_product + NUM_ECC_DIGITS)) /* While c1 != 0 */
    {
        uint64_t l_carry = 0;
        uint i;
        
        vli_clear(l_tmp);
        vli_clear(l_tmp + NUM_ECC_DIGITS);
        omega_mult(l_tmp, p_product + NUM_ECC_DIGITS); /* tmp = w * c1 */
        vli_clear(p_product + NUM_ECC_DIGITS); /* p = c0 */
        
        /* (c1, c0) = c0 + w * c1 */
        for(i=0; i<NUM_ECC_DIGITS+3; ++i)
        {
            uint64_t l_sum = p_product[i] + l_tmp[i] + l_carry;
            if(l_sum != p_product[i])
            {
                l_carry = (l_sum < p_product[i]);
            }
            p_product[i] = l_sum;
        }
    }
    
    while(vli_cmp(p_product, curve_p) > 0)
    {
        vli_sub(p_product, p_product, curve_p);
    }
    vli_set(p_result, p_product);
}

#endif

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_product[2 * NUM_ECC_DIGITS];
    vli_mult(l_product, p_left, p_right);
    vli_mmod_fast(p_result, l_product);
}

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint64_t *p_result, uint64_t *p_left)
{
    uint64_t l_product[2 * NUM_ECC_DIGITS];
    vli_square(l_product, p_left);
    vli_mmod_fast(p_result, l_product);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod)
{
    uint64_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
    uint64_t l_carry;
    int l_cmpResult;
    
    if(vli_isZero(p_input))
    {
        vli_clear(p_result);
        return;
    }

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    
    while((l_cmpResult = vli_cmp(a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if(vli_cmp(u, v) < 0)
            {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
        else
        {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if(vli_cmp(v, u) < 0)
            {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x8000000000000000ull;
            }
        }
    }
    
    vli_set(p_result, u);
}

/* ------ 点运算 ------ */

/* 判断点是否为无穷远点，如果是返回1，否则返回0 */
static int EccPoint_isZero(EccPoint *p_point)
{
    // 如果x和y坐标都为0，则该点为无穷远点
    return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
}

/* 使用蒙哥马利梯度算法进行点倍乘，使用共Z坐标。
   参考：http://eprint.iacr.org/2011/338.pdf
*/

/* 在原地进行点倍乘 */
static void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uint64_t t4[NUM_ECC_DIGITS];
    uint64_t t5[NUM_ECC_DIGITS];
    
    // 如果Z为0，表示该点为无穷远点，直接返回
    if(vli_isZero(Z1))
    {
        return;
    }
    
    // 计算中间变量
    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */
    
    // 计算x3
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */
    
    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    // 如果最低位为1，则加模p后右移1位，否则直接右移1位
    if(vli_testBit(X1, 0))
    {
        uint64_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[NUM_ECC_DIGITS-1] |= l_carry << 63;
    }
    else
    {
        vli_rshift1(X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */
    
    // 计算最终结果
    vli_modSquare_fast(Z1, X1);      /* t3 = B^2 */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
    vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
    vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */
    
    // 更新X1, Y1, Z1
    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}

/* 将点 (x1, y1) 转换为 (x1 * z^2, y1 * z^3) */
static void apply_z(uint64_t *X1, uint64_t *Y1, uint64_t *Z)
{
    uint64_t t1[NUM_ECC_DIGITS];

    // 计算 z^2
    vli_modSquare_fast(t1, Z);    
    // 更新 x1 = x1 * z^2
    vli_modMult_fast(X1, X1, t1); 
    // 计算 z^3
    vli_modMult_fast(t1, t1, Z);  
    // 更新 y1 = y1 * z^3
    vli_modMult_fast(Y1, Y1, t1); 
}
/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ)
{
    uint64_t z[NUM_ECC_DIGITS];
    
    vli_set(X2, X1);
    vli_set(Y2, Y1);
    
    vli_clear(z);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(z, p_initialZ);
    }

    apply_z(X1, Y1, z);
    
    EccPoint_double_jacobian(X1, Y1, z);
    
    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint64_t t5[NUM_ECC_DIGITS];
    
    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */
    
    vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
    vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */
    vli_modSub(X2, X2, X1, curve_p); /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2);    /* t2 = y1*(C - B) */
    vli_modSub(X2, X1, t5, curve_p); /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint64_t t5[NUM_ECC_DIGITS];
    uint64_t t6[NUM_ECC_DIGITS];
    uint64_t t7[NUM_ECC_DIGITS];
    
    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y2 - y1 */

    vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 */
    vli_modSub(X2, X2, t6, curve_p); /* t3 = x3 */
    
    vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */
    
    vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */
    vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */
    
    vli_set(X1, t7);
}

/**
 * 椭圆曲线点乘法
 * 
 * 参数：
 * EccPoint *p_result：输出的椭圆曲线点（结果）
 * EccPoint *p_point：输入的椭圆曲线点
 * uint64_t *p_scalar：标量值（私钥或随机数）
 * uint64_t *p_initialZ：初始Z值（用于优化计算）
 * 
 * 说明：
 * 该函数计算椭圆曲线上的点乘法：result = scalar * point。
 * 使用了蒙哥马利梯度算法（Montgomery Ladder）进行优化，确保计算过程的恒定时间复杂度。
 */
static void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ)
{
    /* R0 和 R1，用于存储中间结果 */
    uint64_t Rx[2][NUM_ECC_DIGITS]; // 存储点的X坐标
    uint64_t Ry[2][NUM_ECC_DIGITS]; // 存储点的Y坐标
    uint64_t z[NUM_ECC_DIGITS]; // 用于存储最终的Z值

    int i, nb; // 循环变量和位选择变量

    // 初始化R1为输入点
    vli_set(Rx[1], p_point->x); // 设置R1的X坐标
    vli_set(Ry[1], p_point->y); // 设置R1的Y坐标

    // 对R1进行初始双倍运算，得到R0
    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    // 根据标量的位数，从次高位开始逐位处理
    for(i = vli_numBits(p_scalar) - 2; i > 0; --i)
    {
        // 根据当前位的值选择R0或R1
        nb = !vli_testBit(p_scalar, i);
        // 执行条件加法，更新R0或R1
        XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
        // 执行普通加法，更新R0或R1
        XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    }

    // 处理标量的最低位
    nb = !vli_testBit(p_scalar, 0);
    // 执行条件加法，更新最终结果
    XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    
    /* 计算最终的1/Z值 */
    // 计算X1 - X0
    vli_modSub(z, Rx[1], Rx[0], curve_p);
    // 计算Yb * (X1 - X0)
    vli_modMult_fast(z, z, Ry[1-nb]);
    // 计算xP * Yb * (X1 - X0)
    vli_modMult_fast(z, z, p_point->x);
    // 计算1 / (xP * Yb * (X1 - X0))
    vli_modInv(z, z, curve_p);
    // 计算yP / (xP * Yb * (X1 - X0))
    vli_modMult_fast(z, z, p_point->y);
    // 计算Xb * yP / (xP * Yb * (X1 - X0))
    vli_modMult_fast(z, z, Rx[1-nb]);
    /* 结束1/Z计算 */

    // 将最终结果的X和Y坐标转换为标准形式
    XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    
    // 应用Z值，将结果转换为仿射坐标
    apply_z(Rx[0], Ry[0], z);
    
    // 将最终结果存储到输出变量中
    vli_set(p_result->x, Rx[0]);
    vli_set(p_result->y, Ry[0]);
}

static void ecc_bytes2native(uint64_t p_native[NUM_ECC_DIGITS], const uint8_t p_bytes[ECC_BYTES])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        const uint8_t *p_digit = p_bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
        p_native[i] = ((uint64_t)p_digit[0] << 56) | ((uint64_t)p_digit[1] << 48) | ((uint64_t)p_digit[2] << 40) | ((uint64_t)p_digit[3] << 32) |
            ((uint64_t)p_digit[4] << 24) | ((uint64_t)p_digit[5] << 16) | ((uint64_t)p_digit[6] << 8) | (uint64_t)p_digit[7];
    }
}

static void ecc_native2bytes(uint8_t p_bytes[ECC_BYTES], const uint64_t p_native[NUM_ECC_DIGITS])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint8_t *p_digit = p_bytes + 8 * (NUM_ECC_DIGITS - 1 - i);
        p_digit[0] = p_native[i] >> 56;
        p_digit[1] = p_native[i] >> 48;
        p_digit[2] = p_native[i] >> 40;
        p_digit[3] = p_native[i] >> 32;
        p_digit[4] = p_native[i] >> 24;
        p_digit[5] = p_native[i] >> 16;
        p_digit[6] = p_native[i] >> 8;
        p_digit[7] = p_native[i];
    }
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uint64_t a[NUM_ECC_DIGITS])
{
    unsigned i;
    uint64_t p1[NUM_ECC_DIGITS] = {1};
    uint64_t l_result[NUM_ECC_DIGITS] = {1};
    
    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
    for(i = vli_numBits(p1) - 1; i > 1; --i)
    {
        vli_modSquare_fast(l_result, l_result);
        if(vli_testBit(p1, i))
        {
            vli_modMult_fast(l_result, l_result, a);
        }
    }
    vli_set(a, l_result);
}

/**
 * 解压缩椭圆曲线点
 * 
 * 参数：
 * EccPoint *p_point：输出的椭圆曲线点
 * const uint8_t p_compressed[ECC_BYTES+1]：输入的压缩椭圆曲线点
 * 
 * 说明：
 * 压缩椭圆曲线点格式：第一个字节表示点的格式（0x02或0x03），其余字节表示x坐标。
 * 解压缩过程通过计算y坐标来恢复完整的椭圆曲线点。
 */
static void ecc_point_decompress(EccPoint *p_point, const uint8_t p_compressed[ECC_BYTES+1])
{
    uint64_t _3[NUM_ECC_DIGITS] = {3}; /* -a = 3，椭圆曲线方程中的系数 */
    // 将压缩点的x坐标从字节数组转换为本地格式
    ecc_bytes2native(p_point->x, p_compressed+1);
    
    // 计算y坐标
    // 根据椭圆曲线方程 y^2 = x^3 + ax + b，其中a = -3
    vli_modSquare_fast(p_point->y, p_point->x); /* y = x^2 */
    vli_modSub(p_point->y, p_point->y, _3, curve_p); /* y = x^2 - 3 */
    vli_modMult_fast(p_point->y, p_point->y, p_point->x); /* y = x^3 - 3x */
    vli_modAdd(p_point->y, p_point->y, curve_b, curve_p); /* y = x^3 - 3x + b */
    
    // 计算模平方根，得到y坐标
    mod_sqrt(p_point->y);
    
    // 根据压缩点的第一个字节（0x02或0x03）确定y坐标的奇偶性
    // 如果计算出的y坐标的奇偶性与压缩点的第一个字节不匹配，则取其补数
    if((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
    {
        vli_sub(p_point->y, curve_p, p_point->y);
    }
}

int ecc_make_key(uint8_t p_publicKey[ECC_BYTES+1], uint8_t p_privateKey[ECC_BYTES])
{
    uint64_t l_private[NUM_ECC_DIGITS]; // 用于存储私钥的数组
    EccPoint l_public; // 用于存储公钥的椭圆曲线点
    unsigned l_tries = 0; // 尝试生成私钥的次数
    
    // 循环生成私钥，直到生成一个有效的私钥和对应的公钥
    do
    {
        // 生成一个随机数作为私钥
        if(!getRandomNumber(l_private) || (l_tries++ >= MAX_TRIES))
        {
            // 如果生成随机数失败，或者尝试次数超过最大限制，则返回失败
            return 0;
        }
        // 如果生成的随机数为0，则跳过本次循环
        if(vli_isZero(l_private))
        {
            continue;
        }
    
        // 确保私钥在范围 [1, n-1] 内
        // 对于支持的椭圆曲线，n足够大，通常只需要减一次
        if(vli_cmp(curve_n, l_private) != 1)
        {
            vli_sub(l_private, l_private, curve_n);
        }

        // 使用私钥和基点 G 计算公钥
        EccPoint_mult(&l_public, &curve_G, l_private, NULL);
    } while(EccPoint_isZero(&l_public)); // 如果计算出的公钥为零点，则重新生成私钥
    
    // 将私钥从本地格式转换为字节数组格式
    ecc_native2bytes(p_privateKey, l_private);
    // 将公钥的 x 坐标从本地格式转换为字节数组格式
    ecc_native2bytes(p_publicKey + 1, l_public.x);
    // 设置公钥的格式字节，表示这是一个压缩公钥
    // 压缩公钥的第一个字节为 0x02 或 0x03，取决于 y 坐标的奇偶性
    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
    // 返回成功
    return 1;
}

int ecdh_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES])
{
    EccPoint l_public; // 对方的公钥（解压缩后的椭圆曲线点）
    uint64_t l_private[NUM_ECC_DIGITS]; // 自己的私钥（本地格式）
    uint64_t l_random[NUM_ECC_DIGITS]; // 用于点乘运算的随机数
    
    // 生成一个随机数，用于点乘运算的随机化
    if(!getRandomNumber(l_random))
    {
        // 如果生成随机数失败，返回失败
        return 0;
    }
    
    // 将压缩格式的公钥解压缩为椭圆曲线点
    ecc_point_decompress(&l_public, p_publicKey);
    // 将字节数组格式的私钥转换为本地格式
    ecc_bytes2native(l_private, p_privateKey);
    
    // 计算共享密钥
    EccPoint l_product; // 用于存储点乘运算的结果
    // 使用自己的私钥和对方的公钥进行点乘运算，得到共享密钥
    EccPoint_mult(&l_product, &l_public, l_private, l_random);
    
    // 将共享密钥从本地格式转换为字节数组格式
    ecc_native2bytes(p_secret, l_product.x);
    
    // 如果计算出的共享密钥不是零点，则返回成功
    return !EccPoint_isZero(&l_product);
}
/* -------- ECDSA code -------- */

/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_product[2 * NUM_ECC_DIGITS];
    uint64_t l_modMultiple[2 * NUM_ECC_DIGITS];
    uint l_digitShift, l_bitShift;
    uint l_productBits;
    uint l_modBits = vli_numBits(p_mod);
    
    vli_mult(l_product, p_left, p_right);
    l_productBits = vli_numBits(l_product + NUM_ECC_DIGITS);
    if(l_productBits)
    {
        l_productBits += NUM_ECC_DIGITS * 64;
    }
    else
    {
        l_productBits = vli_numBits(l_product);
    }
    
    if(l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(p_result, l_product);
        return;
    }
    
    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(l_modMultiple);
    vli_clear(l_modMultiple + NUM_ECC_DIGITS);
    l_digitShift = (l_productBits - l_modBits) / 64;
    l_bitShift = (l_productBits - l_modBits) % 64;
    if(l_bitShift)
    {
        l_modMultiple[l_digitShift + NUM_ECC_DIGITS] = vli_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift);
    }
    else
    {
        vli_set(l_modMultiple + l_digitShift, p_mod);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(p_result);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while(l_productBits > NUM_ECC_DIGITS * 64 || vli_cmp(l_modMultiple, p_mod) >= 0)
    {
        int l_cmp = vli_cmp(l_modMultiple + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS);
        if(l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product) <= 0))
        {
            if(vli_sub(l_product, l_product, l_modMultiple))
            { /* borrow */
                vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, p_result);
            }
            vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, l_modMultiple + NUM_ECC_DIGITS);
        }
        uint64_t l_carry = (l_modMultiple[NUM_ECC_DIGITS] & 0x01) << 63;
        vli_rshift1(l_modMultiple + NUM_ECC_DIGITS);
        vli_rshift1(l_modMultiple);
        l_modMultiple[NUM_ECC_DIGITS-1] |= l_carry;
        
        --l_productBits;
    }
    vli_set(p_result, l_product);
}

static uint umax(uint a, uint b)
{
    return (a > b ? a : b);
}

int ecdsa_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2])
{
    uint64_t k[NUM_ECC_DIGITS]; // 随机数 k
    uint64_t l_tmp[NUM_ECC_DIGITS]; // 临时变量
    uint64_t l_s[NUM_ECC_DIGITS]; // 用于计算 s
    EccPoint p; // 椭圆曲线上的点
    unsigned l_tries = 0; // 尝试次数

    // 生成随机数 k
    do
    {
        if(!getRandomNumber(k) || (l_tries++ >= MAX_TRIES))
        {
            return 0; // 如果生成失败或尝试次数过多，返回错误
        }
        if(vli_isZero(k))
        {
            continue; // 如果 k 为零，重新生成
        }

        // 确保 k 在 [1, n-1] 范围内
        if(vli_cmp(curve_n, k) != 1)
        {
            vli_sub(k, k, curve_n);
        }

        // 计算 P = k * G
        EccPoint_mult(&p, &curve_G, k, NULL);

        // 计算 r = x1 (mod n)
        if(vli_cmp(curve_n, p.x) != 1)
        {
            vli_sub(p.x, p.x, curve_n);
        }
    } while(vli_isZero(p.x)); // 确保 r 不为零

    // 将 r 存储到签名中
    ecc_native2bytes(p_signature, p.x);

    // 计算 s = (e + r * d) / k (mod n)
    ecc_bytes2native(l_tmp, p_privateKey); // 将私钥 d 转换为本地格式
    vli_modMult(l_s, p.x, l_tmp, curve_n); // s = r * d
    ecc_bytes2native(l_tmp, p_hash); // 将哈希值 e 转换为本地格式
    vli_modAdd(l_s, l_tmp, l_s, curve_n); // s = e + r * d
    vli_modInv(k, k, curve_n); // k = 1 / k
    vli_modMult(l_s, l_s, k, curve_n); // s = (e + r * d) / k

    // 将 s 存储到签名中
    ecc_native2bytes(p_signature + ECC_BYTES, l_s);

    return 1; // 签名成功
}

int ecdsa_verify(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2])
{
    uint64_t u1[NUM_ECC_DIGITS], u2[NUM_ECC_DIGITS];
    uint64_t z[NUM_ECC_DIGITS];
    EccPoint l_public, l_sum;
    uint64_t rx[NUM_ECC_DIGITS];
    uint64_t ry[NUM_ECC_DIGITS];
    uint64_t tx[NUM_ECC_DIGITS];
    uint64_t ty[NUM_ECC_DIGITS];
    uint64_t tz[NUM_ECC_DIGITS];
    
    uint64_t l_r[NUM_ECC_DIGITS], l_s[NUM_ECC_DIGITS];
    
    ecc_point_decompress(&l_public, p_publicKey);
    ecc_bytes2native(l_r, p_signature);
    ecc_bytes2native(l_s, p_signature + ECC_BYTES);
    
    if(vli_isZero(l_r) || vli_isZero(l_s))
    { /* r, s must not be 0. */
        return 0;
    }
    
    if(vli_cmp(curve_n, l_r) != 1 || vli_cmp(curve_n, l_s) != 1)
    { /* r, s must be < n. */
        return 0;
    }

    /* Calculate u1 and u2. */
    vli_modInv(z, l_s, curve_n); /* Z = s^-1 */
    ecc_bytes2native(u1, p_hash);
    vli_modMult(u1, u1, z, curve_n); /* u1 = e/s */
    vli_modMult(u2, l_r, z, curve_n); /* u2 = r/s */
    
    /* Calculate l_sum = G + Q. */
    vli_set(l_sum.x, l_public.x);
    vli_set(l_sum.y, l_public.y);
    vli_set(tx, curve_G.x);
    vli_set(ty, curve_G.y);
    vli_modSub(z, l_sum.x, tx, curve_p); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, l_sum.x, l_sum.y);
    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(l_sum.x, l_sum.y, z);
    
    /* Use Shamir's trick to calculate u1*G + u2*Q */
    EccPoint *l_points[4] = {NULL, &curve_G, &l_public, &l_sum};
    uint l_numBits = umax(vli_numBits(u1), vli_numBits(u2));
    
    EccPoint *l_point = l_points[(!!vli_testBit(u1, l_numBits-1)) | ((!!vli_testBit(u2, l_numBits-1)) << 1)];
    vli_set(rx, l_point->x);
    vli_set(ry, l_point->y);
    vli_clear(z);
    z[0] = 1;

    int i;
    for(i = l_numBits - 2; i >= 0; --i)
    {
        EccPoint_double_jacobian(rx, ry, z);
        
        int l_index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
        EccPoint *l_point = l_points[l_index];
        if(l_point)
        {
            vli_set(tx, l_point->x);
            vli_set(ty, l_point->y);
            apply_z(tx, ty, z);
            vli_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            vli_modMult_fast(z, z, tz);
        }
    }

    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(rx, ry, z);
    
    /* v = x1 (mod n) */
    if(vli_cmp(curve_n, rx) != 1)
    {
        vli_sub(rx, rx, curve_n);
    }

    /* Accept only if v == r. */
    return (vli_cmp(rx, l_r) == 0);
}