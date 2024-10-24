#include <iostream>
#include <string>

using namespace std;

class RC4
{
private:
    unsigned char S[256];

    void swap(unsigned char& a, unsigned char& b)
    {
        unsigned char temp = a;
        a = b;
        b = temp;
    }

    void initSBox(string key)
    {
        // 初始化 S 盒
        for (unsigned int i = 0; i < 256; ++i)
        {
            S[i] = i;
        }

        unsigned char T[256] = { 0 };
        unsigned keyLength = key.size();
        // 根据密钥初始化 T 表
        for (int i = 0; i < 256; ++i)
        {
            T[i] = key[i % keyLength];
        }

        // 打乱 S 盒
        for (int i = 0, j = 0; i < 256; ++i)
        {
            j = (j + S[i] + T[i]) % 256;
            swap(S[i], S[j]);
        }
    }

public:
    void encryptOrDecrypt(string& data, string key)
    {
        initSBox(key);
        unsigned int dataLength = data.size();
        unsigned char i = 0, j = 0, k, t;
        for (unsigned int h = 0; h < dataLength; ++h)
        {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            swap(S[i], S[j]);
            
            t = (S[i] + S[j]) % 256;
            k = S[t];
            data[h] ^= k;
        }
    }
};

int main()
{
    RC4 rc4;
    string data, key;
    data = "栾佳凝";
    key = "555aaad";
    rc4.encryptOrDecrypt(data, key);
    std::cout << "加密值：" << data << endl;
    rc4.encryptOrDecrypt(data, key);
    cout << "解密值：" << data << endl;
}