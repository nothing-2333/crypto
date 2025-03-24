#pragma once

#include <stdint.h>

typedef struct
{
	uint32_t count[2];
	uint32_t state[4];
	uint8_t buffer[64];
} ctx;

void md5Init(ctx *context);
void md5Update(ctx *context, uint8_t *input, uint32_t inputlen);
void md5Finish(ctx *context, uint8_t digest[16]);
void md5(uint8_t *input, uint32_t inputlen, uint8_t output[16]);