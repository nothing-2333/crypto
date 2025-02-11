#include <stdio.h>

#include "XXTEA.h"

int main()
{
	uint32_t value[2] = { 1, 2 };
	uint32_t const key[4] = { 1, 2, 3, 4 };
	unsigned int n = 2;

	printf("加密前原始数据：%x %x\n", value[0], value[1]);
	encrypt(n, value, key);
	printf("加密后数据：%x %x\n", value[0], value[1]);
	decrypt(n, value, key);
	printf("解密后数据：%x %x\n", value[0], value[1]);

	return 0; 
}
