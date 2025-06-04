#include <string.h>

#include "base64.h"

#define PADDING '='

static const char en_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

static const char de_table[] = {
    /* nul, soh, stx, etx, eot, enq, ack, bel, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
        255, 255, 255, 255, 255, 255, 255, 255,

    /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
        255, 255, 255, 255, 255, 255, 255, 255,

    /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
        255, 255, 255, 255, 255, 255, 255, 255,

    /*  sp, '!', '"', '#', '$', '%', '&', ''', */
        255, 255, 255, 255, 255, 255, 255, 255,

    /* '(', ')', '*', '+', ',', '-', '.', '/', */
        255, 255, 255,  62, 255, 255, 255,  63,

    /* '0', '1', '2', '3', '4', '5', '6', '7', */
        52,  53,  54,  55,  56,  57,  58,  59,

    /* '8', '9', ':', ';', '<', '=', '>', '?', */
        60,  61, 255, 255, 255, 255, 255, 255,

    /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
        255,   0,   1,  2,   3,   4,   5,    6,

    /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
            7,   8,   9,  10,  11,  12,  13,  14,

    /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
        15,  16,  17,  18,  19,  20,  21,  22,

    /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
        23,  24,  25, 255, 255, 255, 255, 255,

    /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
        255,  26,  27,  28,  29,  30,  31,  32,

    /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
        33,  34,  35,  36,  37,  38,  39,  40,

    /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
        41,  42,  43,  44,  45,  46,  47,  48,

    /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
        49,  50,  51, 255, 255, 255, 255, 255
};

unsigned int base64_encode(const unsigned char *in, char *out)
{
    unsigned int len = strlen(in);

    unsigned int state = 0;
    unsigned char last = 0;
    unsigned int i, j;


    for (i = 0, j = 0; i < len; i++)
    {
        unsigned char c = in[i];

        switch (state)
        {
        case 0:
            state = 1;
            out[j++] = en_table[(c >> 2) & 0x3f];
            break;
        
        case 1:
            state = 2;
            out[j++] = en_table[((last & 0x3) << 4) | ((c >> 4) & 0xf)];
            break;

        case 2:
            state = 0;
            out[j++] = en_table[((last & 0xf) << 2) | ((c >> 6) & 0x3)];
            out[j++] = en_table[c & 0x3f];
            break;
        }
        last = c;
    }

    switch (state)
    {
    case 1:
        out[j++] = en_table[(last & 0x3) << 4];
        out[j++] = PADDING;
        out[j++] = PADDING;
        break;
    
    case 2:
        out[j++] = en_table[(last & 0xf) << 2];
        out[j++] = PADDING;
        break;
    }
    out[j] = 0;

    return j;
}

unsigned int base64_decode(const unsigned char *in, char *out)
{
    unsigned int len = strlen(in);
    if (len % 4 != 0) return 0; 

    unsigned int state = 0;
    unsigned char last = 0;
    unsigned int i, j;

    for (i = 0, j = 0; i < len && in[i] != PADDING; ++i)
    {
        unsigned char c = de_table[(unsigned char)in[i]];

        switch (i & 0x3)    // % 4
        {
        case 0:
            out[j] = (c << 2) & 0xff;
            break;
        case 1:
            out[j] |= (c >> 4) & 0x3;
            j++;
            out[j] = (c & 0xf)  << 4;
            break;
        case 2:
            out[j] |= (c >> 2) & 0xf;
            j++;
            out[j] = (c & 0x3) << 6;
            break;
        case 3:
            out[j] |= c;
            j++;
            break;
        }
    }
    return j;
}