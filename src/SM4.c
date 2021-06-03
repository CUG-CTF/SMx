#include "SMx.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

sm4_ctx *sm4_enc_init(SM4_MODE mode, const byte *key, const byte *iv)
{
    typedef const EVP_CIPHER *(*cipher_mode)(void);
    static cipher_mode modes[] = {EVP_sm4_ecb, EVP_sm4_cbc, EVP_sm4_cfb, EVP_sm4_ofb, EVP_sm4_ctr};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, modes[mode](), key, iv);
    return ctx;
}
void sm4_enc_update(sm4_ctx *ctx, byte *out, size_t *olen, const byte *in, const size_t ilen)
{
    *olen = 0;
    EVP_EncryptUpdate(ctx, out, (int *)olen, in, ilen);
}
void sm4_enc_final(sm4_ctx *ctx, byte *out, size_t *olen)
{
    *olen = 0;
    EVP_EncryptFinal(ctx, out, (int *)olen);
    EVP_CIPHER_CTX_free(ctx);
}

void sm4_enc(SM4_MODE mode, const byte *key, const byte *iv, byte *out, size_t *olen, const byte *in, const size_t ilen)
{
    size_t pos = 0, len = 0;
    sm4_ctx *ctx = sm4_enc_init(mode, key, iv);
    sm4_enc_update(ctx, out, &len, in, ilen);
    pos += len, len = 0;
    sm4_enc_final(ctx, out + pos, &len);
    pos += len;
    *olen = pos;
}

sm4_ctx *sm4_dec_init(SM4_MODE mode, const byte *key, const byte *iv)
{
    typedef const EVP_CIPHER *(*cipher_mode)(void);
    static cipher_mode modes[] = {EVP_sm4_ecb, EVP_sm4_cbc, EVP_sm4_cfb, EVP_sm4_ofb, EVP_sm4_ctr};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, modes[mode](), key, iv);
    return ctx;
}
void sm4_dec_update(sm4_ctx *ctx, byte *out, size_t *olen, const byte *in, const size_t ilen)
{
    *olen = 0;
    EVP_DecryptUpdate(ctx, out, (int *)olen, in, ilen);
}
void sm4_dec_final(sm4_ctx *ctx, byte *out, size_t *olen)
{
    *olen = 0;
    EVP_DecryptFinal(ctx, out, (int *)olen);
    EVP_CIPHER_CTX_free(ctx);
}

void sm4_dec(SM4_MODE mode, const byte *key, const byte *iv, byte *out, size_t *olen, const byte *in, const size_t ilen)
{
    size_t pos = 0, len = 0;
    sm4_ctx *ctx = sm4_dec_init(mode, key, iv);
    sm4_dec_update(ctx, out, &len, in, ilen);
    pos += len, len = 0;
    sm4_dec_final(ctx, out + pos, &len);
    pos += len;
    *olen = pos;
}

void sm4_get_random_iv(byte *iv)
{
    RAND_priv_bytes(iv, SM4_BLOCK_SIZE);
}

void sm4_get_key_from_password(const byte *passwd, const size_t len, const byte *salt, const size_t saltlen, int iter, byte *key)
{
    PKCS5_PBKDF2_HMAC(passwd, (int)len, salt, saltlen, iter, EVP_sm3(), SM4_BLOCK_SIZE, key);
}