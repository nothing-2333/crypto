#include <stdio.h>

#include "RC4.h"

int main()
{

    char data[] = "nothing";
    const char *key = "123";
    
    rc4_encrypt(data, 7, key, 3);
    printf("加密值: %s\r\n", data);
    rc4_encrypt(data, 7, key, 3);
    printf("解密值: %s\r\n", data);
}