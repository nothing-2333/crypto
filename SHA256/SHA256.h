#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t  buf[64];
    uint32_t hash[8];
    uint32_t bits[2];
    uint32_t len;
    uint32_t rfu__;
    uint32_t W[64];
} sha256_context;

void sha256_init(sha256_context *ctx);
void sha256_hash(sha256_context *ctx, const void *data, size_t len);
void sha256_done(sha256_context *ctx, uint8_t *hash);

void sha256(const void *data, size_t len, uint8_t *hash);