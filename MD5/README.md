# MD5

## 整体梳理
总的来说只有三步(这句话好熟悉) `md5Init` `md5Update` `md5Finish`:
```c
void md5(uint8_t *input, uint32_t inputlen, uint8_t output[16])
{
    ctx context;
    md5Init(&context);
    md5Update(&context, input, inputlen);
    md5Finish(&context, output);
}
```
先来看看 `md5Init`:
```c
typedef struct
{
	uint32_t count[2];
	uint32_t state[4];
	uint8_t buffer[64];
} ctx;

void md5Init(ctx *context) {
	context->count[0] = 0;
	context->count[1] = 0;
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
}
```
初始化 `ctx` 结构体, 有一些特征值, 再来看看 `md5Update`:
```c
void md5Update(ctx *context, uint8_t *input, uint32_t inputlen)
{
	uint32_t i = 0, index = 0, partlen = 0;
	index = (context->count[0] >> 3) & 0x3F;
	partlen = 64 - index;

	context->count[0] += inputlen << 3;
	if(context->count[0] < (inputlen << 3)) {
		context->count[1]++;
	}
	context->count[1] += inputlen >> 29;

	if(inputlen >= partlen) {
		memcpy(&context->buffer[index], input, partlen);
		transform(context->state, context->buffer);
		for(i = partlen; i + 64 <= inputlen; i += 64) {
			transform(context->state, &input[i]);
		}
		index = 0;
	} else {
		i = 0;
	}
	
	memcpy(&context->buffer[index], &input[i], inputlen - i);
}

void transform(uint32_t state[4], uint8_t block[64]) {
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t x[64];

	uIntArrayToBytes(x, block, 64);

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

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
```
先来看看这段:
```c
uint32_t i = 0, index = 0, partlen = 0;
index = (context->count[0] >> 3) & 0x3F;
partlen = 64 - index;
```
`context->count` 是位计数器, 所以 `context->count[0] >> 3` 算出来的是字节数, 通过 `(context->count[0] >> 3) & 0x3F` 就计算出了缓冲区 `context->buffer` 中已有的字节数, MD5 是以 64 字节一分组, 即 `context->buffer` 长度也为 64 字节, `partlen = 64 - index` 就计算了缓冲区剩余空间。

然后是更新 `context->count`:
```c
// 更新已处理的总数据量（以位为单位）
context->count[0] += inputlen << 3; // 将输入长度从字节转换为位
if(context->count[0] < (inputlen << 3)) {
	// 如果溢出（即超过了 2^32 位），则更新高位计数器
	context->count[1]++;
}
// 更新高位计数器（处理超过 2^32 位的部分）
context->count[1] += inputlen >> 29;
```
最后:
```c
if(inputlen >= partlen) {
	memcpy(&context->buffer[index], input, partlen);
	transform(context->state, context->buffer);
	for(i = partlen; i + 64 <= inputlen; i += 64) {
		transform(context->state, &input[i]);
	}
	index = 0;
} else {
	i = 0;
}

memcpy(&context->buffer[index], &input[i], inputlen - i);
```
如果输入的明文长度足够将缓冲区填满(`inputlen >= partlen`), 那么不断的将明文按 64 字节为一分组使用 `transform` 函数将明文“揉进” `context->state` 中, 如果明文不足 64 字节(包括刚输入进来就不足 64 字节和运算到最后明文剩余不足 64 字节), 将剩余字节复制到缓冲区。

再来看 `md5Finish` 函数:
```c
uint8_t PADDING[] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5Finish(ctx *context, uint8_t digest[16]) {
	uint32_t index = 0, padlen = 0;
	uint8_t bits[8];
	index = (context->count[0] >> 3) & 0x3F;
	padlen = (index < 56)?(56-index):(120-index);
	bytesToUIntArray(bits, context->count, 8);
	md5Update(context, PADDING, padlen);
	md5Update(context, bits, 8);
	bytesToUIntArray(digest, context->state, 16);
}
void bytesToUIntArray(uint8_t *output, uint32_t *input, uint32_t len) {
	uint32_t i = 0, j = 0;
	while(j < len) {
		output[j] = input[i] & 0xFF; // 小端序
		output[j+1] = (input[i] >> 8) & 0xFF;
		output[j+2] = (input[i] >> 16) & 0xFF;
		output[j+3] = (input[i] >> 24) & 0xFF;
		i++;
		j+=4;
	}
}
```
首先看:
```c
index = (context->count[0] >> 3) & 0x3F;
padlen = (index < 56)?(56-index):(120-index);
```
如果缓冲区剩余长度 + 1(0x80) >= 56, 即在缓冲区填入一个 0x80 后, 剩余长度不足 8 字节, 无法将位计数器 `context->count` 存入, 那么就多来一个分组: 
- 第一个分组是 `缓冲区剩余长度 + 0x80 + 用 0 填充到 64 字节` 然后用 `transform` “揉进”  `context->state` 中。
- 第二个分组是 `最后 8 字节存放 context->count + 剩余用 0 填充` 再进行 `transform` “揉进”  `context->state` 中
如果在缓冲区填入一个 0x80 后, 剩余长度足够 8 字节, 可以将位计数器 `context->count` 存入, 那么就 `缓冲区剩余长度 + 0x80 + 最后 8 字节存放 context->count + 剩余用 0 填充` 再进行 `transform` “揉进”  `context->state` 中

值得一提的是 `context->count` 是以小端序存入。

大功告成。

## 特点总结
### 特点一
常量值：
```c
// state 初始化的常量值
context->state[0] = 0x67452301;
context->state[1] = 0xEFCDAB89;
context->state[2] = 0x98BADCFE;
context->state[3] = 0x10325476;

// transform 中出现的常量值
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
密文长度: `uint32_t state[4]` 4 * 4 == 16 字节, hex 字符串长度则为 32
```c
typedef struct
{
	uint32_t count[2];
	uint32_t state[4];
	uint8_t buffer[64];
} ctx;
```

### 特点五
`transform` 中最后通过 += 运算将结果放入 `state` 中：
```c
state[0] += a;
state[1] += b;
state[2] += c;
state[3] += d;
```

### 特点六
分组长度为 64 字节