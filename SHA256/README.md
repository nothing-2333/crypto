# SHA256

## 整体梳理
总的来说只有三步 `sha256_init`, `sha256_hash`, `sha256_done`:
```c
void sha256(const void *data, size_t len, uint8_t *hash)
{
    sha256_context ctx;

    sha256_init(&ctx);
    sha256_hash(&ctx, data, len);
    sha256_done(&ctx, hash);
} // sha256
```
先来看 `sha256_init`:
```c
typedef struct {
    uint8_t  buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[64];
} sha256_context;

void sha256_init(sha256_context *ctx)
{
    if (ctx != NULL) {
        ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
        ctx->hash[0] = 0x6a09e667;
        ctx->hash[1] = 0xbb67ae85;
        ctx->hash[2] = 0x3c6ef372;
        ctx->hash[3] = 0xa54ff53a;
        ctx->hash[4] = 0x510e527f;
        ctx->hash[5] = 0x9b05688c;
        ctx->hash[6] = 0x1f83d9ab;
        ctx->hash[7] = 0x5be0cd19;
    }
} // sha256_init
```
初始化 `sha256_context` 结构体, 有一些特征值。再来看看 `sha256_hash`:
```c
void sha256_hash(sha256_context *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    if ((ctx != NULL) && (bytes != NULL) && (ctx->len < sizeof(ctx->buf))) {
        for (size_t i = 0; i < len; i++) {
            // 将当前字节存入上下文的缓冲区中
            ctx->buf[ctx->len++] = bytes[i];
            if (ctx->len == sizeof(ctx->buf)) {
                _hash(ctx);
                _addbits(ctx, sizeof(ctx->buf) * 8);
                ctx->len = 0;
            }
        }
    }
}

static void _hash(sha256_context *ctx)
{
    register uint32_t a, b, c, d, e, f, g, h;
    uint32_t t[2];

    a = ctx->hash[0];
    b = ctx->hash[1];
    c = ctx->hash[2];
    d = ctx->hash[3];
    e = ctx->hash[4];
    f = ctx->hash[5];
    g = ctx->hash[6];
    h = ctx->hash[7];

    for (uint32_t i = 0; i < 64; i++) {
        if (i < 16) ctx->W[i] = _word(&ctx->buf[_shw(i, 2)]);
        else ctx->W[i] = _G1(ctx->W[i - 2]) + ctx->W[i - 7] + _G0(ctx->W[i - 15]) + ctx->W[i - 16];

        t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + ctx->W[i];
        t[1] = _S0(a) + _Ma(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t[0];
        d = c;
        c = b;
        b = a;
        a = t[0] + t[1];
    }

    ctx->hash[0] += a;
    ctx->hash[1] += b;
    ctx->hash[2] += c;
    ctx->hash[3] += d;
    ctx->hash[4] += e;
    ctx->hash[5] += f;
    ctx->hash[6] += g;
    ctx->hash[7] += h;
} // _hash

// 内部函数，用于更新 SHA256 上下文中的位计数器
static void _addbits(sha256_context *ctx, uint32_t n)
{
    // 检查低32位的位计数器是否会溢出
    if (ctx->bits[0] > (0xffffffff - n)) {
        // 如果低32位溢出，高32位加1
        ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
    }
    // 更新低32位的位计数器，确保其值在 0 到 0xFFFFFFFF 之间
    ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
} // _addbits
```
`_hash` 中一些子函数没有列全, 后续会在特点总结列出, `sha256_hash` 总的来说就是将明文按 64 字节一组进行哈希, 经过一顿运算将明文信息“揉进” `ctx->hash` 中。不足 64 的部分放进缓冲区后不在管, 交给 `sha256_done` 函数:
```c
void sha256_done(sha256_context *ctx, uint8_t *hash)
{
    register uint32_t i, j;

    if (ctx != NULL) {
        // 计算当前缓冲区中已填充数据的偏移量
        j = ctx->len % sizeof(ctx->buf);
        // 在缓冲区中添加填充字节 0x80
        ctx->buf[j] = 0x80;
        // 将缓冲区剩余部分填充为 0x00
        for (i = j + 1; i < sizeof(ctx->buf); i++) {
            ctx->buf[i] = 0x00;
        }
        // 如果缓冲区中已填充的数据长度超过 55 字节（SHA256 块大小 64 字节 - 8 字节的位计数器）
        if (ctx->len > 55) {
            // 对当前缓冲区进行一次哈希处理
            _hash(ctx);
             // 清空缓冲区，以便后续填充位计数器
            for (j = 0; j < sizeof(ctx->buf); j++) {
                ctx->buf[j] = 0x00;
            }
        }

        // 更新位计数器，将已处理的字节数转换为位数（每字节 8 位）
        _addbits(ctx, ctx->len * 8);
        // 将位计数器的低 32 位和高 32 位分别存储到缓冲区的最后 8 字节中, 大端序
        ctx->buf[63] = _shb(ctx->bits[0],  0);
        ctx->buf[62] = _shb(ctx->bits[0],  8);
        ctx->buf[61] = _shb(ctx->bits[0], 16);
        ctx->buf[60] = _shb(ctx->bits[0], 24);
        ctx->buf[59] = _shb(ctx->bits[1],  0);
        ctx->buf[58] = _shb(ctx->bits[1],  8);
        ctx->buf[57] = _shb(ctx->bits[1], 16);
        ctx->buf[56] = _shb(ctx->bits[1], 24);
        // 对包含位计数器的缓冲区进行最后一次哈希处理
        _hash(ctx);

        if (hash != NULL) {
            for (i = 0, j = 24; i < 4; i++, j -= 8) {
                // 将 ctx->hash 中的 32 位哈希值逐字节提取并以小端序的方式存储到输出缓冲区 hash 中
                hash[i +  0] = _shb(ctx->hash[0], j);
                hash[i +  4] = _shb(ctx->hash[1], j);
                hash[i +  8] = _shb(ctx->hash[2], j);
                hash[i + 12] = _shb(ctx->hash[3], j);
                hash[i + 16] = _shb(ctx->hash[4], j);
                hash[i + 20] = _shb(ctx->hash[5], j);
                hash[i + 24] = _shb(ctx->hash[6], j);
                hash[i + 28] = _shb(ctx->hash[7], j);
            }
        }
    }
} // sha256_done

// 用于从一个32位整数中提取指定位置的8位字节
FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
    return ((x >> (n & 31)) & 0xff);
} // _shb
```
SHA256 的收尾工作, 总结就是, 就是先在缓冲区 `ctx->buf` 后面加一个 0x80， 如果此时 `ctx->buf` 剩余的部分不足 8 字节(等同于 `ctx->len > 55`), 即没有空间存放存放位计数器(`ctx->bits`), 那么会进行两次 `_hash`: 
- 剩余 + 0x80 + 用 0 填充将缓冲区到 64 字节, 然后 `_hash`, 将信息“揉进” `ctx->hash` 中
- 最后 8 字节存放位计数器(`ctx->bits`)的低 32 位和高 32 位, 其余填充 0, 然后 `_hash`, 将信息“揉进” `ctx->hash` 中
如果缓冲区 `ctx->buf` 剩余的部分大于或等于 8 字节, 即有空间存放存放位计数器(`ctx->bits`), 只会进行一次 `_hash`:
- 剩余 + 0x80 + 用 0 填充将缓冲区到 56 字节 + 最后 8 字节存放位计数器(`ctx->bits`)的低 32 位和高 32 位, 然后 `_hash`, 将信息“揉进” `ctx->hash` 中。

值得一提的是 `ctx->bits` 是以大端序存入。

大功告成。

## 特点总结
### 特点一
初始化特征值 & 固定值:
```c
ctx->hash[0] = 0x6a09e667;
ctx->hash[1] = 0xbb67ae85;
ctx->hash[2] = 0x3c6ef372;
ctx->hash[3] = 0xa54ff53a;
ctx->hash[4] = 0x510e527f;
ctx->hash[5] = 0x9b05688c;
ctx->hash[6] = 0x1f83d9ab;
ctx->hash[7] = 0x5be0cd19;

// _hash 中用到
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
```

### 特点二
`_hash` 加密核心逻辑: 
```c
// -----------------------------------------------------------------------------
// 将 32 位整数 x 左移 n 位，并确保结果仍然是 32 位
FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
    return ((x << (n & 31)) & 0xffffffff);
} // _shw


// -----------------------------------------------------------------------------
// 将 32 位整数 x 循环右移 n 位
FN_ uint32_t _r(uint32_t x, uint8_t n)
{
    return ((x >> n) | _shw(x, 32 - n));
} // _r


// -----------------------------------------------------------------------------
FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ ((~x) & z));
} // _Ch


// -----------------------------------------------------------------------------
FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) ^ (x & z) ^ (y & z));
} // _Ma


// -----------------------------------------------------------------------------
// 计算 Sigma0(x) = _r(x, 2) ^ _r(x, 13) ^ _r(x, 22) 返回 x 循环右移 2 位、13 位和 22 位的结果的异或
FN_ uint32_t _S0(uint32_t x)
{
    return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
} // _S0


// -----------------------------------------------------------------------------
// 计算 Sigma1(x) = _r(x, 6) ^ _r(x, 11) ^ _r(x, 25) 返回 x 循环右移 6 位、11 位和 25 位的结果的异或
FN_ uint32_t _S1(uint32_t x)
{
    return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
} // _S1


// -----------------------------------------------------------------------------
// 计算小 sigma0(x) = _r(x, 7) ^ _r(x, 18) ^ (x >> 3) 返回 x 循环右移 7 位、18 位和右移 3 位的结果的异或
FN_ uint32_t _G0(uint32_t x)
{
    return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
} // _G0


// -----------------------------------------------------------------------------
// 计算小 sigma1(x) = _r(x, 17) ^ _r(x, 19) ^ (x >> 10) 返回 x 循环右移 17 位、19 位和右移 10 位的结果的异或
FN_ uint32_t _G1(uint32_t x)
{
    return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
} // _G1


// -----------------------------------------------------------------------------
// 将 4 个字节的数组转换为一个 32 位整数（小端序）
FN_ uint32_t _word(uint8_t *c)
{
    return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
} // _word

// SHA256 哈希计算主循环
for (uint32_t i = 0; i < 64; i++) {
    // 初始化消息计划数组 W
    if (i < 16) {
        // 对于前 16 个元素，直接从缓冲区中提取 32 位整数
        ctx->W[i] = _word(&ctx->buf[_shw(i, 2)]);
    } else {
        // 对于后续元素，使用消息计划扩展公式计算
        ctx->W[i] = _G1(ctx->W[i - 2]) + ctx->W[i - 7] + _G0(ctx->W[i - 15]) + ctx->W[i - 16];
    }

    // 计算临时变量 t[0] 和 t[1]
    t[0] = h + _S1(e) + _Ch(e, f, g) + K[i] + ctx->W[i]; // 主压缩函数的一部分
    t[1] = _S0(a) + _Ma(a, b, c);                        // 主压缩函数的另一部分

    // 更新哈希值变量
    h = g;
    g = f;
    f = e;
    e = d + t[0]; // 更新 e 的值
    d = c;
    c = b;
    b = a;
    a = t[0] + t[1]; // 更新 a 的值
}
```

### 特点三
`_hash` 中最后通过 += 运算将结果放入`hash`中：
```c
ctx->hash[0] += a;
ctx->hash[1] += b;
ctx->hash[2] += c;
ctx->hash[3] += d;
ctx->hash[4] += e;
ctx->hash[5] += f;
ctx->hash[6] += g;
ctx->hash[7] += h;
```

### 特点四
密文长度: `uint32_t hash[8]` 4 * 8 == 32 字节, hex 字符串长度则为 64
```c
typedef struct {
    uint8_t  buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[64];
} sha256_context;
```

### 特点五
填充规则(具体可以看上边关于 `sha256_done` 中填充的分析, 这里只写结论): (明文长度 + 1(0x80)) % 64, 如果大于 56:
- 明文剩余 + 0x80 + 用 0 填充到 64 字节, 进行 `_hash`
- 最后 8 字节以大端序存放明文比特数(明文长度 * 8), 其余用 0 填充, 进行 `_hash`
如果小于等于 56:
- 明文剩余 + 0x80 + 用 0 填充到 56 字节 + 最后 8 字节以大端序存放明文比特数(明文长度 * 8), 进行 `_hash`

### 特点六
分组长度为 64 字节
