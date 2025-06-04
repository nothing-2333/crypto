#include <stdio.h>

#include "TEA.h"


int main()
{
	uint32_t v[2] = { 1, 2 };
	uint32_t k[4] = { 1, 2, 3, 4};

	printf("加密前的数据：%x %x\n", v[0], v[1]);
	tea_encrypt(v, k);
	printf("加密后数据：%x %x\n", v[0], v[1]);
	tea_decrypt(v, k);
	printf("解密后数据：%x %x\n", v[0], v[1]);
	
	return 0;
}