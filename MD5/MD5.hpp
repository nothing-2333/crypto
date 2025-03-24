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

