#include "SMx.h"
#include <openssl/evp.h>

sm3_hash_ctx *sm3_hash_init()
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sm3());
    return ctx;
}
void sm3_hash_update(sm3_hash_ctx *ctx, const byte *data, const size_t len)
{
    EVP_DigestUpdate(ctx, data, len);
}
void sm3_hash_final(sm3_hash_ctx *ctx, byte *hash)
{
    EVP_DigestFinal(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}
void sm3_hash(const byte *data, const size_t len, byte *hash)
{
    sm3_hash_ctx *ctx = sm3_hash_init();
    sm3_hash_update(ctx, data, len);
    sm3_hash_final(ctx, hash);
}

#if 0
struct sm3_hmac_ctx
{
    uint8_t key[SM3_BLOCK_SIZE];
    sm3_hash_ctx *md_ctx;
};
sm3_hmac_ctx *sm3_hmac_init(byte *key, size_t klen)
{
    const uint8_t ipad = 0x36;
    sm3_hmac_ctx *ctx = malloc(sizeof(sm3_hmac_ctx));
    if (!ctx) return NULL;
    if (klen < SM3_BLOCK_SIZE)
    {
        memcpy(ctx->key, key, klen);
        memset(ctx->key + klen, 0, SM3_BLOCK_SIZE - klen);
    }
    else
    {
        sm3_hash(key, klen, ctx->key);
        memset(ctx->key + SM3_HASH_SIZE, SM3_BLOCK_SIZE - SM3_HASH_SIZE, 0);
    }
    for (size_t i = 0; i < SM3_BLOCK_SIZE; i++)
        ctx->key[i] ^= ipad;
    ctx->md_ctx = sm3_hash_init();
    sm3_hash_update(ctx->md_ctx, ctx->key, SM3_BLOCK_SIZE);
    return ctx;
}
void sm3_hmac_update(sm3_hmac_ctx *ctx, byte *data, size_t dlen)
{
    sm3_hash_update(ctx->md_ctx, data, dlen);
}
void sm3_hmac_final(sm3_hmac_ctx *ctx, byte *hmac)
{
    const uint8_t ipad = 0x36, opad = 0x5c;
    sm3_hash_final(ctx->md_ctx, hmac);
    for (size_t i = 0; i < SM3_BLOCK_SIZE; i++)
        ctx->key[i] ^= (ipad ^ opad);
    ctx->md_ctx = sm3_hash_init();
    sm3_hash_update(ctx->md_ctx, ctx->key, SM3_BLOCK_SIZE);
    sm3_hash_update(ctx->md_ctx, hmac, SM3_HASH_SIZE);
    sm3_hash_final(ctx->md_ctx, hmac);
    free(ctx);
}
#endif

sm3_hmac_ctx *sm3_hmac_init(const byte *key, const size_t klen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, klen);
    EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_PKEY_free(pkey);
    return ctx;
}
void sm3_hmac_update(sm3_hmac_ctx *ctx, const byte *data, const size_t dlen)
{
    EVP_DigestSignUpdate(ctx, data, dlen);
}
void sm3_hmac_final(sm3_hmac_ctx *ctx, byte *hmac)
{
    size_t dummy;
    EVP_DigestSignFinal(ctx, hmac, &dummy);
    EVP_MD_CTX_free(ctx);
}
void sm3_hmac(const byte *data, const size_t dlen, const byte *key, const size_t klen, byte *hmac)
{
    sm3_hmac_ctx *ctx = sm3_hmac_init(key, klen);
    sm3_hmac_update(ctx, data, dlen);
    sm3_hmac_final(ctx, hmac);
}