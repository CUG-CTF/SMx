#pragma once
#ifndef _SMx_H_
#define _SMx_H_
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define _CRT_BEGIN_C_HEADER \
    extern "C"              \
    {
#define _CRT_END_C_HEADER }
#else
#define _BEGIN_C_HEADER
#define _END_C_HEADER
#endif

_BEGIN_C_HEADER

typedef uint8_t byte;

// SM2
typedef struct evp_pkey_st sm2_pkey;

/**
 * @brief generate sm2 keypair
 * @param private_key store hex-formatted private key
 * @param public_key store hex-formatted public key
*/
void sm2_generate_keypair(char *private_key, char *public_key);

/**
 * @brief get private key pointer from hex
 * @param private_key private key hex
 * @return private key pointer
*/
sm2_pkey *sm2_get_private_key(const char *private_key);

/**
 * @brief get public key pointer from hex
 * @param public_key public key hex
 * @return public key pointer
*/
sm2_pkey *sm2_get_public_key(const char *public_key);

/**
 * @brief get keypair pointer from hex. SM2 signing requires both private key and public key.
 * @param private_key private key hex
 * @param public_key public key hex
 * @return keypair pointer
*/
sm2_pkey *sm2_get_keypair(const char *private_key, const char *public_key);

/**
 * @brief free a key pointer
 * @param key key pointer
*/
void sm2_free_pkey(sm2_pkey *key);

/**
 * @brief asymmetric encrypt message using peer's pubkey
 * @param public_key public_key hex
 * @param out encrypted result
 * @param olen encrypted result's length
 * @param in message
 * @param ilen message length
*/
void sm2_enc(const char *public_key, byte *out, size_t *olen, const byte *in, const size_t ilen);

/**
 * @brief asymmetric decrypt message using self prikey
 * @param private_key private_key hex
 * @param out orginal message
 * @param olen orginal message length
 * @param in cipher text
 * @param ilen cipher text length
*/
void sm2_dec(const char *private_key, byte *out, size_t *olen, const byte *in, const size_t ilen);

void sm2_sign_msg(const char *private_key, const char *public_key, byte *sig, size_t *sig_len, const byte *msg, const size_t len);

int sm2_verify_msg(const char *public_key, const byte *sig, const size_t sig_len, const byte *msg, const size_t len);

// SM3
#define SM3_HASH_SIZE (256 >> 3)
#define SM3_BLOCK_SIZE (512 >> 3)

typedef struct evp_md_ctx_st sm3_hash_ctx;
sm3_hash_ctx *sm3_hash_init();
void sm3_hash_update(sm3_hash_ctx *ctx, const byte *data, const size_t len);
void sm3_hash_final(sm3_hash_ctx *ctx, byte *hash);
void sm3_hash(const byte *data, const size_t len, byte *hash);

typedef struct evp_md_ctx_st sm3_hmac_ctx;
sm3_hmac_ctx *sm3_hmac_init(const byte *key, const size_t klen);
void sm3_hmac_update(sm3_hmac_ctx *ctx, const byte *data, const size_t dlen);
void sm3_hmac_final(sm3_hmac_ctx *ctx, byte *hmac);
void sm3_hmac(const byte *data, const size_t dlen, const byte *key, const size_t klen, byte *hash);

// SM4

#define SM4_BLOCK_SIZE 16

typedef enum
{
    sm4_ecb,
    sm4_cbc,
    sm4_cfb,
    sm4_ofb,
    sm4_ctr,
} SM4_MODE;

typedef struct evp_cipher_ctx_st sm4_ctx;

sm4_ctx *sm4_enc_init(SM4_MODE mode, const byte *key, const byte *iv);
void sm4_enc_update(sm4_ctx *ctx, byte *out, size_t *olen, const byte *in, const size_t ilen);
void sm4_enc_final(sm4_ctx *ctx, byte *out, size_t *olen);
void sm4_enc(SM4_MODE mode, const byte *key, const byte *iv, byte *out, size_t *olen, const byte *in, const size_t ilen);

sm4_ctx *sm4_dec_init(SM4_MODE mode, const byte *key, const byte *iv);
void sm4_dec_update(sm4_ctx *ctx, byte *out, size_t *olen, const byte *in, const size_t ilen);
void sm4_dec_final(sm4_ctx *ctx, byte *out, size_t *olen);
void sm4_dec(SM4_MODE mode, const byte *key, const byte *iv, byte *out, size_t *olen, const byte *in, const size_t ilen);

void sm4_get_random_iv(byte *iv);

void sm4_get_key_from_password(const byte *passwd, const size_t len, const byte *salt, const size_t saltlen, int iter, byte *key);

_END_C_HEADER

#endif // !_SMx_H_
