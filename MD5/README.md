# MD5

## 整体梳理
作为一个消息摘要算法，整个算法的核心思想是，输入的信息64字节为一组都“揉进”`uint32_t state[4]`中，然后在将这个`state` hex 编码。

关键的辅助函数`md5Update` `md5Finish`，`md5Update`负责将输入长度超出64字节的部分，分成64字节为一组进行加密，最后不足64字节不予处理。`md5Finish`负责处理最后不足64字节的部分，将它们按规则填充到64字节再加密，然后将`state`转化输出。

核心加密函数`transform`，将64字节加密，放到`state`中。

## 特点梳理
### 特点一
`state`初始化常量：
```c
context->state[0] = 0x67452301;
context->state[1] = 0xEFCDAB89;
context->state[2] = 0x98BADCFE;
context->state[3] = 0x10325476;
```
### 特点二
最后的填充：0x80, 0, 0 ... 0, 最后8字节是输入的总长度。
### 特点三
运算：
```c
static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) | (~x & z));
}

static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & z) | (y & ~z));
}

static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
    return (x ^ y ^ z);
}

static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
    return (y ^ (x | ~z));
}

static inline uint32_t ROTATE_LEFT(uint32_t x, uint32_t n) {
    return ((x << n) | (x >> (32 - n)));
}

static inline void FF(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    *a += F(b, c, d) + x + ac;
    *a = ROTATE_LEFT(*a, s);
    *a += b;
}

static inline void GG(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    *a += G(b, c, d) + x + ac;
    *a = ROTATE_LEFT(*a, s);
    *a += b;
}

static inline void HH(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    *a += H(b, c, d) + x + ac;
    *a = ROTATE_LEFT(*a, s);
    *a += b;
}

static inline void II(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
    *a += I(b, c, d) + x + ac;
    *a = ROTATE_LEFT(*a, s);
    *a += b;
}
```
### 特点四
固定常量与固定循环左移位数：
```c
FF(&a,  b,  c,  d,  x[ 0],  7,  0xd76aa478);
FF(&d,  a,  b,  c,  x[ 1],  12,  0xe8c7b756);
FF(&c,  d,  a,  b,  x[ 2],  17,  0x242070db);
FF(&b,  c,  d,  a,  x[ 3],  22,  0xc1bdceee);
FF(&a,  b,  c,  d,  x[ 4],  7,  0xf57c0faf);
FF(&d,  a,  b,  c,  x[ 5],  12,  0x4787c62a);
FF(&c,  d,  a,  b,  x[ 6],  17,  0xa8304613);
FF(&b,  c,  d,  a,  x[ 7],  22,  0xfd469501);
FF(&a,  b,  c,  d,  x[ 8],  7,  0x698098d8);
FF(&d,  a,  b,  c,  x[ 9],  12,  0x8b44f7af);
FF(&c,  d,  a,  b,  x[10],  17,  0xffff5bb1);
FF(&b,  c,  d,  a,  x[11],  22,  0x895cd7be);
FF(&a,  b,  c,  d,  x[12],  7,  0x6b901122);
FF(&d,  a,  b,  c,  x[13],  12,  0xfd987193);
FF(&c,  d,  a,  b,  x[14],  17,  0xa679438e);
FF(&b,  c,  d,  a,  x[15],  22,  0x49b40821);

GG(&a,  b,  c,  d,  x[ 1],  5,  0xf61e2562);
GG(&d,  a,  b,  c,  x[ 6],  9,  0xc040b340);
GG(&c,  d,  a,  b,  x[11],  14,  0x265e5a51);
GG(&b,  c,  d,  a,  x[ 0],  20,  0xe9b6c7aa);
GG(&a,  b,  c,  d,  x[ 5],  5,  0xd62f105d);
GG(&d,  a,  b,  c,  x[10],  9,   0x2441453);
GG(&c,  d,  a,  b,  x[15],  14,  0xd8a1e681);
GG(&b,  c,  d,  a,  x[ 4],  20,  0xe7d3fbc8);
GG(&a,  b,  c,  d,  x[ 9],  5,  0x21e1cde6);
GG(&d,  a,  b,  c,  x[14],  9,  0xc33707d6);
GG(&c,  d,  a,  b,  x[ 3],  14,  0xf4d50d87);
GG(&b,  c,  d,  a,  x[ 8],  20,  0x455a14ed);
GG(&a,  b,  c,  d,  x[13],  5,  0xa9e3e905);
GG(&d,  a,  b,  c,  x[ 2],  9,  0xfcefa3f8);
GG(&c,  d,  a,  b,  x[ 7],  14,  0x676f02d9);
GG(&b,  c,  d,  a,  x[12],  20,  0x8d2a4c8a);

HH(&a,  b,  c,  d,  x[ 5],  4,  0xfffa3942);
HH(&d,  a,  b,  c,  x[ 8],  11,  0x8771f681);
HH(&c,  d,  a,  b,  x[11],  16,  0x6d9d6122);
HH(&b,  c,  d,  a,  x[14],  23,  0xfde5380c);
HH(&a,  b,  c,  d,  x[ 1],  4,  0xa4beea44);
HH(&d,  a,  b,  c,  x[ 4],  11,  0x4bdecfa9);
HH(&c,  d,  a,  b,  x[ 7],  16,  0xf6bb4b60);
HH(&b,  c,  d,  a,  x[10],  23,  0xbebfbc70);
HH(&a,  b,  c,  d,  x[13],  4,  0x289b7ec6);
HH(&d,  a,  b,  c,  x[ 0],  11,  0xeaa127fa);
HH(&c,  d,  a,  b,  x[ 3],  16,  0xd4ef3085);
HH(&b,  c,  d,  a,  x[ 6],  23,   0x4881d05);
HH(&a,  b,  c,  d,  x[ 9],  4,  0xd9d4d039);
HH(&d,  a,  b,  c,  x[12],  11,  0xe6db99e5);
HH(&c,  d,  a,  b,  x[15],  16,  0x1fa27cf8);
HH(&b,  c,  d,  a,  x[ 2],  23,  0xc4ac5665);

II(&a,  b,  c,  d,  x[ 0],  6,  0xf4292244);
II(&d,  a,  b,  c,  x[ 7],  10,  0x432aff97);
II(&c,  d,  a,  b,  x[14],  15,  0xab9423a7);
II(&b,  c,  d,  a,  x[ 5],  21,  0xfc93a039);
II(&a,  b,  c,  d,  x[12],  6,  0x655b59c3);
II(&d,  a,  b,  c,  x[ 3],  10,  0x8f0ccc92);
II(&c,  d,  a,  b,  x[10],  15,  0xffeff47d);
II(&b,  c,  d,  a,  x[ 1],  21,  0x85845dd1);
II(&a,  b,  c,  d,  x[ 8],  6,  0x6fa87e4f);
II(&d,  a,  b,  c,  x[15],  10,  0xfe2ce6e0);
II(&c,  d,  a,  b,  x[ 6],  15,  0xa3014314);
II(&b,  c,  d,  a,  x[13],  21,  0x4e0811a1);
II(&a,  b,  c,  d,  x[ 4],  6,  0xf7537e82);
II(&d,  a,  b,  c,  x[11],  10,  0xbd3af235);
II(&c,  d,  a,  b,  x[ 2],  15,  0x2ad7d2bb);
II(&b,  c,  d,  a,  x[ 9],  21,  0xeb86d391);
```
### 特点五
`sm3_process`中最后通过 += 运算将结果放入`state`中：
```c
state[0] += a;
state[1] += b;
state[2] += c;
state[3] += d;
```