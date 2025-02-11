#include<stdio.h>

#include "XTEA.h"

int main(){
	uint32_t value[2] = { 1, 2 };
	uint32_t const key[4] = { 1, 2, 3, 4 };
	unsigned int num_rounds = 32;

	printf("加密前原始数据：%x %x\n", value[0], value[1]);
	encrypt(num_rounds, value, key);
	printf("加密后原始数据：%x %x\n", value[0], value[1]);
	decrypt(num_rounds, value, key);
	printf("解密后原始数据：%x %x\n", value[0], value[1]);
    
	return 0;
}
