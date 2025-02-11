#include <stdio.h>
#include <string.h>

#include "AES.h"

void printASCCI(char *str, int len) 
{
	int c;
	for(int i = 0; i < len; i++) 
    {
		c = (int)*str++;
		c = c & 0xff;
		printf("%x", c);
	}
	printf("\n");
}

int main()
{
    char key[17] = "1234567891234567";
    char data[17] = "1234561234561234";
    printf("%s\n", key);
    encrypt(data, strlen(data), key);
    printASCCI(data, strlen(data));

    return 0;
}