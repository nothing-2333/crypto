#include "SM4.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char** argv)
{
	unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char input[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char output[16];
	sm4_context ctx;
	unsigned long i;

    for (i = 0; i < 16; i++)
        printf("%02x ", input[i]);
    printf("\n");

    // ecb
	sm4_setkey_enc(&ctx, key);
	sm4_crypt_ecb(&ctx, SM4_ENCRYPT, 16, input, output);
	for (i = 0; i < 16; i++)
		printf("%02x ", output[i]);
	printf("\n");

	sm4_setkey_dec(&ctx, key);
	sm4_crypt_ecb(&ctx, SM4_DECRYPT, 16, output, output);
	for (i = 0; i < 16; i++)
		printf("%02x ", output[i]);
	printf("\n");

    // cbc
    unsigned char iv[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    sm4_setkey_enc(&ctx, key);
	sm4_crypt_cbc(&ctx, SM4_ENCRYPT, 16, iv, input, output);
	for (i = 0; i < 16; i++)
		printf("%02x ", output[i]);
	printf("\n");

    unsigned char iv_[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	sm4_setkey_dec(&ctx, key);
	sm4_crypt_cbc(&ctx, SM4_DECRYPT, 16, iv_, output, output);
	for (i = 0; i < 16; i++)
		printf("%02x ", output[i]);
	printf("\n");

	return 0;
}