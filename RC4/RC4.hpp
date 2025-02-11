#pragma once 

#include <string>

class RC4
{
private:
    unsigned char S[256];

    void swap(unsigned char& a, unsigned char& b);

    void initSBox(std::string key);

public:
    void encryptOrDecrypt(std::string& data, std::string key);
};

