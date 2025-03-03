#include <stdio.h>
#include <stdlib.h>

#include "base64.h"


int main()
{
    char in[100] = "nothing";
    char out[100] = {};

    encode(in, out);
    printf("%s\n", out);
    decode(out, in);
    printf("%s\n", in);

    return 0;
}