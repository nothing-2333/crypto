#include <iostream>
#include <string>

#include "RC4.hpp"

int main()
{
    RC4 rc4;
    std::string data, key;
    data = "nothing";
    key = "123";
    rc4.encryptOrDecrypt(data, key);
    std::cout << "加密值：" << data << std::endl;
    rc4.encryptOrDecrypt(data, key);
    std::cout << "解密值：" << data << std::endl;
}