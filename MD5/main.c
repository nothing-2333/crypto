#include <stdio.h>

#include "MD5.h"

int main()
{
    unsigned char *input = "123456e10adc3949ba59abbe56e057f20f883e";
    unsigned char output[16];

    md5(input, 38, output);
    for(int i = 0; i < 16; i++) printf("%02x", output[i]); 
    printf("\n");

    return 0;
}