#pragma once

#include <string>
#include <cstring>

using std::string;

typedef unsigned char u8;
typedef unsigned int u32;

class MD5
{
public:
    MD5(const string& message);

    // md5 digest
    const u8* getDigest();

    // 将 md5 digest 转化为字符串
    string toStr();

private:
    void init(const u8* input, size_t length);

    void transform(const u8 block[64]);

    // 转换数据存储格式
    // usigned int to usigned char
    void encode(const u32* input, u8* output, size_t length);
    // usigned char to usigned int
    void decode(const u8* input, u32* output, size_t length);

    u32 F(u32 b, u32 c, u32 d);
    u32 G(u32 b, u32 c, u32 d);
    u32 H(u32 b, u32 c, u32 d);
    u32 I(u32 b, u32 c, u32 d);

    void FF(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti);
    void GG(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti);
    void HH(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti);
    void II(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti);

    // 循环左移
    u32 shift_left(u32 num, int pos);

private:
    bool finished;

    u32 state[4];

    u32 count[2];

    u8 buffer[64];

    u8 digest[16];

    static const u8 padding[64];

    static const char hexNumbers[16];
};

const u8 MD5::padding[64] = { 0x80 };
const char MD5::hexNumbers[16] = {
  '0', '1', '2', '3',
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  'c', 'd', 'e', 'f'
};

MD5::MD5(const string& message)
{
    finished = false;

    count[0] = count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    init((const u8*)message.c_str(), message.size());
}

// md5 digest
const u8* MD5::getDigest()
{
    if (!finished)
    {
        finished = true;

        u8 bits[8];
        u32 oldState[4];
        u32 oldCount[2];
        u32 index, paddingLength;

        memcpy(oldState, state, 16);
        memcpy(oldCount, count, 8);

        encode(count, bits, 8);
        index = (u32)((count[0] >> 3) & 0x3f);
        paddingLength = (index < 56) ? (56 - index) : (120 - index);
        init(padding, paddingLength);

        init(bits, 8);

        encode(state, digest, 16);

        memcpy(state, oldState, 16);
        memcpy(count, oldCount, 8);
    }
    return digest;
}

// 将 md5 digest 转化为字符串
string MD5::toStr()
{
    const u8* digest_ = getDigest();
    string str;
    str.reserve(16 << 1);
    for (size_t i = 0; i < 16; ++i)
    {
        int t = digest_[i];
        int a = t / 16;
        int b = t % 16;
        str.append(1, hexNumbers[a]);
        str.append(1, hexNumbers[b]);
    }
    return str;
}

void MD5::init(const u8* input, size_t length)
{
    u32 i ,index, partLength;

    finished = false;

    index = (u32)((count[0] >> 3) & 0x3f);

    count[0] += ((u32)length << 3);
    if (count[0] < ((u32)length << 3)) count[1]++;
    count[1] += ((u32)length >> 29);

    partLength = 64 - index;

    if (length >= partLength)
    {
        memcpy(&buffer[index], input, partLength);
        transform(buffer);

        for (i = partLength; i + 63 < length; i += 64)
        {
            transform(&input[i]);
        }
        index = 0;
    }
    else i = 0;

    memcpy(&buffer[index], &input[i], length - i);
}

void MD5::transform(const u8 block[64])
{
    u32 a = state[0], b = state[1], c = state[2], d = state[3];
    u32 x[16];

    decode(block, x, 64);

    u32 s11 =  7;
    u32 s12 =  12;
    u32 s13 =  17;
    u32 s14 =  22;
    u32 s21 =  5;
    u32 s22 =  9;
    u32 s23 =  14;
    u32 s24 =  20;
    u32 s31 =  4;
    u32 s32 =  11;
    u32 s33 =  16;
    u32 s34 =  23;
    u32 s41 =  6;
    u32 s42 =  10;
    u32 s43 =  15;
    u32 s44 =  21;
    /* Round 1 */
    FF (a, b, c, d, x[ 0], s11, 0xd76aa478);
    FF (d, a, b, c, x[ 1], s12, 0xe8c7b756);
    FF (c, d, a, b, x[ 2], s13, 0x242070db);
    FF (b, c, d, a, x[ 3], s14, 0xc1bdceee);
    FF (a, b, c, d, x[ 4], s11, 0xf57c0faf);
    FF (d, a, b, c, x[ 5], s12, 0x4787c62a);
    FF (c, d, a, b, x[ 6], s13, 0xa8304613);
    FF (b, c, d, a, x[ 7], s14, 0xfd469501);
    FF (a, b, c, d, x[ 8], s11, 0x698098d8);
    FF (d, a, b, c, x[ 9], s12, 0x8b44f7af);
    FF (c, d, a, b, x[10], s13, 0xffff5bb1);
    FF (b, c, d, a, x[11], s14, 0x895cd7be);
    FF (a, b, c, d, x[12], s11, 0x6b901122);
    FF (d, a, b, c, x[13], s12, 0xfd987193);
    FF (c, d, a, b, x[14], s13, 0xa679438e);
    FF (b, c, d, a, x[15], s14, 0x49b40821);

    /* Round 2 */
    GG (a, b, c, d, x[ 1], s21, 0xf61e2562);
    GG (d, a, b, c, x[ 6], s22, 0xc040b340);
    GG (c, d, a, b, x[11], s23, 0x265e5a51);
    GG (b, c, d, a, x[ 0], s24, 0xe9b6c7aa);
    GG (a, b, c, d, x[ 5], s21, 0xd62f105d);
    GG (d, a, b, c, x[10], s22,  0x2441453);
    GG (c, d, a, b, x[15], s23, 0xd8a1e681);
    GG (b, c, d, a, x[ 4], s24, 0xe7d3fbc8);
    GG (a, b, c, d, x[ 9], s21, 0x21e1cde6);
    GG (d, a, b, c, x[14], s22, 0xc33707d6);
    GG (c, d, a, b, x[ 3], s23, 0xf4d50d87);
    GG (b, c, d, a, x[ 8], s24, 0x455a14ed);
    GG (a, b, c, d, x[13], s21, 0xa9e3e905);
    GG (d, a, b, c, x[ 2], s22, 0xfcefa3f8);
    GG (c, d, a, b, x[ 7], s23, 0x676f02d9);
    GG (b, c, d, a, x[12], s24, 0x8d2a4c8a);

    /* Round 3 */
    HH (a, b, c, d, x[ 5], s31, 0xfffa3942);
    HH (d, a, b, c, x[ 8], s32, 0x8771f681);
    HH (c, d, a, b, x[11], s33, 0x6d9d6122);
    HH (b, c, d, a, x[14], s34, 0xfde5380c);
    HH (a, b, c, d, x[ 1], s31, 0xa4beea44);
    HH (d, a, b, c, x[ 4], s32, 0x4bdecfa9);
    HH (c, d, a, b, x[ 7], s33, 0xf6bb4b60);
    HH (b, c, d, a, x[10], s34, 0xbebfbc70);
    HH (a, b, c, d, x[13], s31, 0x289b7ec6);
    HH (d, a, b, c, x[ 0], s32, 0xeaa127fa);
    HH (c, d, a, b, x[ 3], s33, 0xd4ef3085);
    HH (b, c, d, a, x[ 6], s34,  0x4881d05);
    HH (a, b, c, d, x[ 9], s31, 0xd9d4d039);
    HH (d, a, b, c, x[12], s32, 0xe6db99e5);
    HH (c, d, a, b, x[15], s33, 0x1fa27cf8);
    HH (b, c, d, a, x[ 2], s34, 0xc4ac5665);

    /* Round 4 */
    II (a, b, c, d, x[ 0], s41, 0xf4292244);
    II (d, a, b, c, x[ 7], s42, 0x432aff97);
    II (c, d, a, b, x[14], s43, 0xab9423a7);
    II (b, c, d, a, x[ 5], s44, 0xfc93a039);
    II (a, b, c, d, x[12], s41, 0x655b59c3);
    II (d, a, b, c, x[ 3], s42, 0x8f0ccc92);
    II (c, d, a, b, x[10], s43, 0xffeff47d);
    II (b, c, d, a, x[ 1], s44, 0x85845dd1);
    II (a, b, c, d, x[ 8], s41, 0x6fa87e4f);
    II (d, a, b, c, x[15], s42, 0xfe2ce6e0);
    II (c, d, a, b, x[ 6], s43, 0xa3014314);
    II (b, c, d, a, x[13], s44, 0x4e0811a1);
    II (a, b, c, d, x[ 4], s41, 0xf7537e82);
    II (d, a, b, c, x[11], s42, 0xbd3af235);
    II (c, d, a, b, x[ 2], s43, 0x2ad7d2bb);
    II (b, c, d, a, x[ 9], s44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// usigned int to usigned char
void MD5::encode(const u32* input, u8* output, size_t length)
{
  for (size_t i = 0, j = 0; j < length; ++i, j += 4) 
  {
    output[j] = (u8)(input[i] & 0xff);
    output[j + 1] = (u8)((input[i] >> 8) & 0xff);
    output[j + 2] = (u8)((input[i] >> 16) & 0xff);
    output[j + 3] = (u8)((input[i] >> 24) & 0xff);
  }
}
// usigned char to usigned int
void MD5::decode(const u8* input, u32* output, size_t length)
{
  for (size_t i = 0, j = 0; j < length; ++i, j += 4) 
  {
    output[i] = ((u32)input[j]) | (((u32)input[j + 1]) << 8) |
        (((u32)input[j + 2]) << 16) | (((u32)input[j + 3]) << 24);
  }
}

u32 MD5::F(u32 b, u32 c, u32 d)
{   
    return (b & c) | ((~b) & d);
}
u32 MD5::G(u32 b, u32 c, u32 d)
{
    return (b & d) | (c & (~d)); 
}
u32 MD5::H(u32 b, u32 c, u32 d)
{
    return (b ^ c ^ d);
}
u32 MD5::I(u32 b, u32 c, u32 d)
{
    return (c ^ (b | ~d));
}

void MD5::FF(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti)
{
    a = shift_left(a + F(b, c, d) + x + Ti, s) + b;
}
void MD5::GG(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti)
{
    a = shift_left(a + G(b, c, d) + x + Ti, s) + b;
}
void MD5::HH(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti)
{
    a = shift_left(a + H(b, c, d) + x + Ti, s) + b;
}
void MD5::II(u32& a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 Ti)
{
    a = shift_left(a + I(b, c, d) + x + Ti, s) + b;
}

u32 MD5::shift_left(u32 num, int pos)
{
    return (num << pos) | (num >> (32 - pos));
}