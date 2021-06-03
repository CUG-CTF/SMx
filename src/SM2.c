#include "SMx.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <string.h>

void sm2_generate_keypair(char *private_key, char *public_key)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_KEY_generate_key(key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
    const BIGNUM *pri_key = EC_KEY_get0_private_key(key);
    char *pri_hex = BN_bn2hex(pri_key);
    char *pub_hex = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_COMPRESSED, NULL);
    strcpy(private_key, pri_hex);
    strcpy(public_key, pub_hex);
    OPENSSL_free(pri_hex);
    OPENSSL_free(pub_hex);
    EC_KEY_free(key);
}

sm2_pkey *sm2_get_private_key(const char *private_key)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    BIGNUM *pri_key = NULL;
    BN_hex2bn(&pri_key, private_key);
    EC_KEY_set_private_key(key, pri_key);
    BN_free(pri_key);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, key);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    return pkey;
}
sm2_pkey *sm2_get_public_key(const char *public_key)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    EC_POINT *pub_key = EC_POINT_hex2point(group, public_key, NULL, NULL);
    EC_KEY_set_public_key(key, pub_key);
    EC_POINT_free(pub_key);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, key);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    return pkey;
}

sm2_pkey *sm2_get_keypair(const char *private_key, const char *public_key)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    BIGNUM *pri_key = NULL;
    BN_hex2bn(&pri_key, private_key);
    EC_KEY_set_private_key(key, pri_key);
    BN_free(pri_key);

    EC_POINT *pub_key = EC_POINT_hex2point(group, public_key, NULL, NULL);
    EC_KEY_set_public_key(key, pub_key);
    EC_POINT_free(pub_key);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, key);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    return pkey;
}

void sm2_free_pkey(sm2_pkey *key)
{
    EVP_PKEY_free(key);
}

void sm2_enc(const char *public_key, byte *out, size_t *olen, const byte * in, const size_t ilen)
{
    sm2_pkey *pkey = sm2_get_public_key(public_key);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    *olen = 0;
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt(ctx, out, olen, in, ilen);

    sm2_free_pkey(pkey);
    EVP_PKEY_CTX_free(ctx);
}

void sm2_dec(const char *private_key, byte *out, size_t *olen, const byte * in, const size_t ilen)
{
    sm2_pkey *pkey = sm2_get_private_key(private_key);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    *olen = 0;
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt(ctx, out, olen, in, ilen);

    sm2_free_pkey(pkey);
    EVP_PKEY_CTX_free(ctx);
}

void sm2_sign_msg(const char *private_key, const char *public_key, byte *sig, size_t *sig_len, const byte *msg, const size_t len)
{
    sm2_pkey *pkey = sm2_get_keypair(private_key, public_key);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, NULL, 0);
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);

    EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestSignUpdate(ctx, msg, len);
    EVP_DigestSignFinal(ctx, sig, sig_len);

    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);
}

int sm2_verify_msg(const char *public_key, const byte * sig, const size_t sig_len, const byte * msg, const size_t len)
{
    sm2_pkey *pkey = sm2_get_public_key(public_key);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, NULL, 0);
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);

    EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestVerifyUpdate(ctx, msg, len);
    int result = EVP_DigestVerifyFinal(ctx, sig, sig_len);

    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);
    return result;
}