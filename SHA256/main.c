#include <stdio.h>
#include <string.h>

#include "SHA256.h"

int main()
{
    uint8_t *input = "123456";
    uint8_t output[32];

    sha256(input, strlen(input), output);
    for (int i = 0; i < 32; i++) printf("%02x", output[i]);
	printf("\n");
    
    return 0;
}