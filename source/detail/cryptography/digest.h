/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_IS_BIG_ENDIAN 1

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64
#define SHA1_STATE_WORDS (SHA1_DIGEST_SIZE / sizeof(uint32_t))

typedef struct
{
    uint32_t state[SHA1_STATE_WORDS];
    uint64_t nblocks;
    uint8_t block[SHA1_BLOCK_SIZE];
    size_t num;
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t datalen);
void sha1_finish(SHA1_CTX *ctx, uint8_t dgst[SHA1_DIGEST_SIZE]);
void sha1_digest(const uint8_t *data, size_t datalen, uint8_t dgst[SHA1_DIGEST_SIZE]);

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128
#define SHA512_STATE_WORDS 8

typedef struct
{
    uint64_t state[SHA512_STATE_WORDS];
    uint64_t nblocks;
    uint8_t block[SHA512_BLOCK_SIZE];
    size_t num;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t datalen);
void sha512_finish(SHA512_CTX *ctx, uint8_t dgst[SHA512_DIGEST_SIZE]);
void sha512_digest(const uint8_t *data, size_t datalen,
    uint8_t dgst[SHA512_DIGEST_SIZE]);

typedef struct DIGEST DIGEST;
typedef struct DIGEST_CTX DIGEST_CTX;

#define DIGEST_MAX_SIZE 64
#define DIGEST_MAX_BLOCK_SIZE (1024 / 8)

struct DIGEST_CTX
{
    union
    {
        SHA1_CTX sha1_ctx;
        SHA512_CTX sha512_ctx;
    } u;
    const DIGEST *digest;
};

struct DIGEST
{
    size_t digest_size;
    size_t block_size;
    size_t ctx_size;
    int (*init)(DIGEST_CTX *ctx);
    int (*update)(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
    int (*finish)(DIGEST_CTX *ctx, uint8_t *dgst);
};

const DIGEST *DIGEST_sha1(void);
const DIGEST *DIGEST_sha512(void);
int digest_init(DIGEST_CTX *ctx, const DIGEST *algor);
int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen);
int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen);
int digest(const DIGEST *digest, const uint8_t *data, size_t datalen, uint8_t *dgst, size_t *dgstlen);

#ifdef __cplusplus
}
#endif