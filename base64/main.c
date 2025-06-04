#include <stdio.h>
#include <stdlib.h>

#include "base64.h"


int main()
{
    char in[100] = "nothing";
    char out[100] = {};

    base64_encode(in, out);
    printf("%s\n", out);
    base64_decode(out, in);
    printf("%s\n", in);

    return 0;
}