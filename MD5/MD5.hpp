#pragma once

#include <string>
#include <iostream>
#include <cstring>

class MD5
{
public:
    MD5(std::string& str);
    MD5() {};
    ~MD5() {};

    // 更新函数
    void update(const unsigned char* inputStr, int strLength);
    // 展示结果
    void showResult();
    // 加密
    void encode(std::string& str);

private:
    // 四个寄存器，MD缓冲区，共128位
    unsigned int state[4];
    // 统计长度，仅保留前64位
    unsigned int count[2];
    // 输入
    unsigned char buffer[512];
    // 输出
    unsigned char digest[128];
    // 填充标记
    bool isPadding;
    // 输出32位结果
    char result[33];

    // 初始化
    void initialize(std::string& str);
    // 对一个区做变换
    void transform(unsigned char block[64]);
    // 填充函数，增加长度
    void padding();
    // unsigned char 与 unsigned int 相互转换
    void int2char(unsigned char* output, const unsigned int* input, int length);
    void char2int(unsigned int* output, const unsigned char* input, int length);
    // 循环左移
    unsigned int shiftLeft(unsigned int num, int pos);
    // 轮函数
    unsigned int F(unsigned int b, unsigned int c, unsigned int d);
    unsigned int G(unsigned int b, unsigned int c, unsigned int d);
    unsigned int H(unsigned int b, unsigned int c, unsigned int d);
    unsigned int I(unsigned int b, unsigned int c, unsigned int d);
    // 压缩函数
	void HF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti);
    void HG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti);
    void HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti);
    void HI(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti);
};

void MD5::initialize(std::string& str)
{
    // 初始化 IV
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    isPadding = false;
    memset(count, 0, sizeof(count));
    memset(digest, 0, sizeof(digest));

    update((unsigned char*)(str.c_str()), str.size());
    padding();

    // 将 4 个 state 结果连接起来放在 digest 中
    int2char(digest, state, 16);
}

MD5::MD5(std::string& str)
{
    initialize(str);
}

void MD5::encode(std::string& str)
{
    // 每次执行前都要初始化一遍
    initialize(str);
}

void MD5::update(const unsigned char* inputStr, int strLength)
{   
    int index = (count[0] >> 3) & 0x3f;

    // 使用 count 时，将 2 个 32 位转换成 64bit 处理
    count[0] += strLength << 3;
    if (count[0] << (strLength << 3)) count[1]++;

    // 需要补齐的长度
    int paddingLength = 64 - index;

    if (strLength >= paddingLength)
    {
        // 将数据放入 buffer 中进行处理
        memcpy(buffer + index, inputStr, paddingLength);
        transform(buffer);

        // 分组处理
        for (int i = paddingLength; 64 + i < strLength; i += 64)
        {
            transform((unsigned char*)inputStr + i);
        }
        index = 0;
    }

    memcpy(buffer + index, inputStr, strLength);
}

void MD5::padding()
{
    unsigned char padding[64] = 
    {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!isPadding)
    {
        unsigned char bits[8];

        // 将 count 转化为 64bit
        int2char(bits, count, 8);

        int index = (count[0] >> 3) & 0x3f;

        // 预留 8 位给 length
        int paddingLength = index < (64 - 8) ? (64 - 8 - index) : (2 * 64 - 8 - index);

        // 填补 padding 数组，长度为 paddingLength 
        update(padding, paddingLength);

        // 对长度 8 位做出处理
        update(padding, 8);

        isPadding = true;
    }

    std::cout << "MD5 加密完成，以下是四个 state 信息" << std::endl; 
    for (int i = 0; i < 4; ++i)
    {
        std::cout << state[i] << std::endl;
    }
}

void MD5::showResult()
{
    // 转化为 16 进制
    result[32] = 0;
    for (int i = 0; i < 16; ++i)
    {
        sprintf(result + i * 2, "%02x", digest[i]);
    }
    std::cout << "加密结果：" << result << std::endl;
}

void MD5::transform(unsigned char block[64])
{
    // 获取 IV 的 state 数据
    unsigned int a = state[0], b = result[1], c = result[2], d = state[3];

    unsigned int x[16];

    // 将 8 位 char 转为 32 位 int
    char2int(x, block, 64);

    // 左循环位移表
    int s[4][4] = 
    {
        { 7, 12, 17, 22 },
        { 5, 9, 14, 20 },
        { 4, 11, 16, 23 },
        { 6, 10, 15, 21 },
    };
    // T 表
    // const unsigned int T[64] = 
    // {
	// 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	// 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	// 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
	// 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	// 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	// 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	// 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	// 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    // };

	HF(a, b, c, d, x[0], s[0][0], 0xd76aa478);
	HF(d, a, b, c, x[1], s[0][1], 0xe8c7b756);
	HF(c, d, a, b, x[2], s[0][2], 0x242070db);
	HF(b, c, d, a, x[3], s[0][3], 0xc1bdceee);
	HF(a, b, c, d, x[4], s[0][0], 0xf57c0faf);
	HF(d, a, b, c, x[5], s[0][1], 0x4787c62a);
	HF(c, d, a, b, x[6], s[0][2], 0xa8304613);
	HF(b, c, d, a, x[7], s[0][3], 0xfd469501); 
	HF(a, b, c, d, x[8], s[0][0], 0x698098d8);
	HF(d, a, b, c, x[9], s[0][1], 0x8b44f7af);
	HF(c, d, a, b, x[10], s[0][2], 0xffff5bb1);
	HF(b, c, d, a, x[11], s[0][3], 0x895cd7be);
	HF(a, b, c, d, x[12], s[0][0], 0x6b901122);
	HF(d, a, b, c, x[13], s[0][1], 0xfd987193);
	HF(c, d, a, b, x[14], s[0][2], 0xa679438e);
	HF(b, c, d, a, x[15], s[0][3], 0x49b40821);
	
	HG(a, b, c, d, x[1], s[1][0], 0xf61e2562);
	HG(d, a, b, c, x[6], s[1][1], 0xc040b340);
	HG(c, d, a, b, x[11], s[1][2], 0x265e5a51);
	HG(b, c, d, a, x[0], s[1][3], 0xe9b6c7aa); 
	HG(a, b, c, d, x[5], s[1][0], 0xd62f105d);
	HG(d, a, b, c, x[10], s[1][1],  0x2441453);
	HG(c, d, a, b, x[15], s[1][2], 0xd8a1e681);
	HG(b, c, d, a, x[4], s[1][3], 0xe7d3fbc8);
	HG(a, b, c, d, x[9], s[1][0], 0x21e1cde6);
	HG(d, a, b, c, x[14], s[1][1], 0xc33707d6);
	HG(c, d, a, b, x[3], s[1][2], 0xf4d50d87);
	HG(b, c, d, a, x[8], s[1][3], 0x455a14ed);
	HG(a, b, c, d, x[13], s[1][0], 0xa9e3e905);
	HG(d, a, b, c, x[2], s[1][1], 0xfcefa3f8);
	HG(c, d, a, b, x[7], s[1][2], 0x676f02d9);
	HG(b, c, d, a, x[12], s[1][3], 0x8d2a4c8a);
 
	HH(a, b, c, d, x[5], s[2][0], 0xfffa3942);
	HH(d, a, b, c, x[8], s[2][1], 0x8771f681);
	HH(c, d, a, b, x[11], s[2][2], 0x6d9d6122);
	HH(b, c, d, a, x[14], s[2][3], 0xfde5380c);
	HH(a, b, c, d, x[1], s[2][0], 0xa4beea44);
	HH(d, a, b, c, x[4], s[2][1], 0x4bdecfa9);
	HH(c, d, a, b, x[7], s[2][2], 0xf6bb4b60);
	HH(b, c, d, a, x[10], s[2][3], 0xbebfbc70);
	HH(a, b, c, d, x[13], s[2][0], 0x289b7ec6);
	HH(d, a, b, c, x[0], s[2][1], 0xeaa127fa); 
	HH(c, d, a, b, x[3], s[2][2], 0xd4ef3085);
	HH(b, c, d, a, x[6], s[2][3],  0x4881d05);
	HH(a, b, c, d, x[9], s[2][0], 0xd9d4d039);
	HH(d, a, b, c, x[12], s[2][1], 0xe6db99e5);
	HH(c, d, a, b, x[15], s[2][2], 0x1fa27cf8);
	HH(b, c, d, a, x[2], s[2][3], 0xc4ac5665);
 
	HI(a, b, c, d, x[0], s[3][0], 0xf4292244);
	HI(d, a, b, c, x[7], s[3][1], 0x432aff97);
	HI(c, d, a, b, x[14], s[3][2], 0xab9423a7);
	HI(b, c, d, a, x[5], s[3][3], 0xfc93a039);
	HI(a, b, c, d, x[12], s[3][0], 0x655b59c3);
	HI(d, a, b, c, x[3], s[3][1], 0x8f0ccc92);
	HI(c, d, a, b, x[10], s[3][2], 0xffeff47d);
	HI(b, c, d, a, x[1], s[3][3], 0x85845dd1);
	HI(a, b, c, d, x[8], s[3][0], 0x6fa87e4f);
	HI(d, a, b, c, x[15], s[3][1], 0xfe2ce6e0);
	HI(c, d, a, b, x[6], s[3][2], 0xa3014314);
	HI(b, c, d, a, x[13], s[3][3], 0x4e0811a1);
	HI(a, b, c, d, x[4], s[3][0], 0xf7537e82);
	HI(d, a, b, c, x[11], s[3][1], 0xbd3af235);
	HI(c, d, a, b, x[2], s[3][2], 0x2ad7d2bb);
	HI(b, c, d, a, x[9], s[3][3], 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

// unsigned char 与 unsigned int 相互转换
void MD5::int2char(unsigned char* output, const unsigned int* input, int length)
{
    for (int i = 0, j = 0; i < length; ++i)
    {
        output[j] = input[i] & 0xff;
        output[j + 1] = (input[i] >> 8) & 0xff;
        output[j + 2] = (input[i] >> 16) & 0xff;
        output[j + 3] = (input[i] >> 24) & 0xff;
        j += 4;
    }
}
void MD5::char2int(unsigned int* output, const unsigned char* input, int length)
{
    for (int i = 0, j = 0; i < length; i += 4)
    {
        output[j] = input[i] | (input[i + 1] << 8) | (input[i + 2] << 16) | (input[i + 4] << 24);
        j++;
    }
}
// 循环左移
unsigned int MD5::shiftLeft(unsigned int num, int pos)
{
    return (num << pos) | (num >> (32 - pos));
}
// 轮函数
unsigned int MD5::F(unsigned int b, unsigned int c, unsigned int d)
{
    return (b & c) | ((~b) & d);
}
unsigned int MD5::G(unsigned int b, unsigned int c, unsigned int d)
{
    return (b & d) | (c & (~d));
}
unsigned int MD5::H(unsigned int b, unsigned int c, unsigned int d)
{
    return (b ^ c ^ d);
}
unsigned int MD5::I(unsigned int b, unsigned int c, unsigned int d)
{
    return (c ^ (b | ~d));
}
// 压缩函数
void MD5::HF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti)
{
    a = shiftLeft(a + F(b, c, d) + x + Ti, s) + b;
}
void MD5::HG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti)
{
    a = shiftLeft(a + G(b, c, d) + x + Ti, s) + b;
}
void MD5::HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti)
{
    a = shiftLeft(a + H(b, c, d) + x + Ti, s) + b;
}
void MD5::HI(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int Ti)
{
    a = shiftLeft(a + I(b, c, d) + x + Ti, s) + b;
}
