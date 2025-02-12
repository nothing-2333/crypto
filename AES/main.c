#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "AES.h"

static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

int main()
{
    uint8_t key[] = "1234567891234567";
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

    AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    phex(in);
    AES_ECB_encrypt_buffer(&ctx, in);
    phex(in);
    AES_ECB_decrypt_buffer(&ctx, in);
    phex(in);

    return 0;
}