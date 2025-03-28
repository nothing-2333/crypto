# ECC

## 整体梳理
ECC 真正的作用是，获得一个只有传输方和接受方都知道密钥，这个密钥可以进行对称加密，然后加密通信。对于原理的理解，这个视频可以帮助你：https://www.bilibili.com/video/BV1BY411M74G?t=12.5
 
第一步，`ecc_make_key`函数生成通信双方的公钥和私钥，这里以 Alice 和 Bob 为例，Alice 的私钥是 a，公钥是 A = a × G，Bob 的私钥是 b，公钥是 B = b × G。

第二步，`ecdh_shared_secret`函数计算共享密钥，共享密钥是 S = (a × b) × G，Alice 和 Bob 通过各自的私钥和对方的公钥计算出相同的共享密钥。到这里其实就可以结束了，有个这个只有 Alice 和 Bob 知道的共享密钥，就可以进行对称加密...

补充，用 ECC 签名，验证消息完整性，`ecdsa_sign`函数进行消息签名，`ecdsa_verify`函数进行验签，Alice 使用私钥 a、随机数 k 和消息的哈希值 H(m) 计算签名 (r,s)。Bob 使用 Alice 的公钥 A、消息的哈希值 H(m) 和签名 (r,s) 进行验证。

## 特点梳理
### 特点一
私钥与公钥长度：私钥是一个随机生成的整数，其长度与椭圆曲线的阶 n 的长度相同，n 是一个非常大的素数，表示椭圆曲线上的点的数量。公钥是通过私钥和基点 G 计算得到的椭圆曲线上的一个点 (x,y) ，完整格式包含 x 坐标和 y 坐标，长度为私钥长度的两倍；压缩格式只包含 x 坐标和一个额外的字节，用于表示 y 坐标的奇偶性，长度为私钥长度 + 1字节。
```c
// 常见长度
#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
```
### 特点二
椭圆曲线方程的常量值：curve_p 是一个大素数，它定义了有限域的大小。所有椭圆曲线上的点的坐标（x 和 y）以及所有运算结果都必须模 p；curve_b 是椭圆曲线方程中的常数项 b；curve_G 是椭圆曲线上的一个特定点，称为基点或生成元，A = a × G，对于给定的椭圆曲线标准，基点 G 是固定的；curve_n 表示椭圆曲线的阶，是基点 G 的阶，即最小的正整数 n，使得 n×G=O，其中 O 是椭圆曲线上的无穷远点。

对于这些常数，标准椭圆曲线的参数是固定的，不能改变。自定义椭圆曲线可以改变但必须满足以下条件：模数 p 必须是大素数，系数 a 和 b 必须满足 4a^3 + 27b^2 ≠ 0 mod p 。基点 G 必须是椭圆曲线上的一个点，且其阶 n 是大素数。
```c
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
```
### 特点三
点运算，即 a × G：
```c
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
```
