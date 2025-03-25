#include <string.h>
#include <stdio.h>

#include "SM3.h"

int main( int argc, char *argv[] )
{
	uint8_t *input = "abcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	int ilen = strlen(input);
	uint8_t output[32];
	int i;
	sm3_context ctx;

	printf("Message: ");
	printf("%s\n", input);

	sm3(input, ilen, output);

	printf("Hash: ");
	for (i = 0; i < 32; i++) printf("%02x", output[i]);
	printf("\n");
}