/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <detail/cryptography/digest.h>
#include <stdio.h>
#include <string.h>

int digest_init(DIGEST_CTX *ctx, const DIGEST *algor)
{
    memset(ctx, 0, sizeof(DIGEST_CTX));
    if (algor == NULL)
    {
        return -1;
    }
    ctx->digest = algor;
    ctx->digest->init(ctx);
    return 1;
}

int digest_update(DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
    if (data == NULL || datalen == 0)
    {
        return 0;
    }
    ctx->digest->update(ctx, data, datalen);
    return 1;
}

int digest_finish(DIGEST_CTX *ctx, uint8_t *dgst, size_t *dgstlen)
{
    if (dgst == NULL || dgstlen == NULL)
    {
        return -1;
    }
    ctx->digest->finish(ctx, dgst);
    *dgstlen = ctx->digest->digest_size;
    return 1;
}

int digest(const DIGEST *digest, const uint8_t *data, size_t datalen,
    uint8_t *dgst, size_t *dgstlen)
{
    DIGEST_CTX ctx;
    if (digest_init(&ctx, digest) != 1
        || digest_update(&ctx, data, datalen) < 0
        || digest_finish(&ctx, dgst, dgstlen) != 1)
    {
        return -1;
    }
    memset(&ctx, 0, sizeof(DIGEST_CTX));
    return 1;
}

static int sha1_digest_init(DIGEST_CTX *ctx)
{
    if (!ctx)
    {
        return -1;
    }
    sha1_init(&ctx->u.sha1_ctx);
    return 1;
}

static int sha1_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
    if (!ctx || (!in && inlen != 0))
    {
        return -1;
    }
    sha1_update(&ctx->u.sha1_ctx, in, inlen);
    return 1;
}

static int sha1_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
    if (!ctx || !dgst)
    {
        return -1;
    }
    sha1_finish(&ctx->u.sha1_ctx, dgst);
    return 1;
}

static const DIGEST sha1_digest_object = {
    SHA1_DIGEST_SIZE,
    SHA1_BLOCK_SIZE,
    sizeof(SHA1_CTX),
    sha1_digest_init,
    sha1_digest_update,
    sha1_digest_finish,
};

const DIGEST *DIGEST_sha1(void)
{
    return &sha1_digest_object;
}

static int sha512_digest_init(DIGEST_CTX *ctx)
{
    if (!ctx)
    {
        return -1;
    }
    sha512_init(&ctx->u.sha512_ctx);
    return 1;
}

static int sha512_digest_update(DIGEST_CTX *ctx, const uint8_t *in, size_t inlen)
{
    if (!ctx || (!in && inlen != 0))
    {
        return -1;
    }
    sha512_update(&ctx->u.sha512_ctx, in, inlen);
    return 1;
}

static int sha512_digest_finish(DIGEST_CTX *ctx, uint8_t *dgst)
{
    if (!ctx || !dgst)
    {
        return -1;
    }
    sha512_finish(&ctx->u.sha512_ctx, dgst);
    return 1;
}

static const DIGEST sha512_digest_object = {
    SHA512_DIGEST_SIZE,
    SHA512_BLOCK_SIZE,
    sizeof(SHA512_CTX),
    sha512_digest_init,
    sha512_digest_update,
    sha512_digest_finish,
};

const DIGEST *DIGEST_sha512(void)
{
    return &sha512_digest_object;
}
