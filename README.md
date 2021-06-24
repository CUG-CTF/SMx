# SMx

This project provides a intuitive api to use SM2, SM3 and SM4 algorithms.

## SM2

SM2 can be used for asymmetric encryption and signing.

In this implementation, both the private and public keys are represented using the hex format.

### key generation

Assume you have 2 `char[]` buffers called `pri_key` and `pub_key`, then you need to call

```c
sm2_generate_keypair(pri_key, pub_key);
```

then the keypair will be stored in these two arrays.


### asymmetric encryption

When you want to encrypt `byte *data` of length `len` using `pub_key` and store the result in `byte out[]`, call

```c
sm2_enc(pub_key, out, &olen, data, len);
```

`olen` will be set to length of ciphertext.

And you can decrypte it in a similar way using `pri_key`.

```c
sm2_dec(pri_key, plaintext, &plen, ciphertext, clen);
```
plaintext will be recovered from ciphertext.

### signing

SM2 signing requires both private key AND public key.

```c
sm2_sign_msg(pri, pub, signature, &sig_len, data, len);
int r = sm2_verify_msg(pub, signature, sig_len, data, len);
```

`sm2_verify_msg` returns a int indicates that if the signature is valid.

If signature is valid, r will be 1 otherwise 0;

## SM3

SM3 is used for hashing and can of course be used for HMAC.

Assume `byte data[len]` or additional `byte key[klen]` for HMAC,

```c
sm3_hash(data, len, hash_result);
sm3_hmac(data, len, key, klen, hmac_result);
```

The length of result will be `SM3_HASH_SIZE`.

## SM4

SM4 is a symmetric block cipher. 

This project implements 5 block mode: 

  - sm4_ecb
  - sm4_cbc
  - sm4_cfb
  - sm4_ofb
  - sm4_ctr

When using some mode, a `SM4_BLOCK_SIZE` bytes iv is required. And for all mode, a `SM4_BLOCK_SIZE` bytes key is required

For convenience, `iv` can be generated using `sm4_get_random_iv` and `key` can be generated using `sm4_get_key_from_password` which uses PBKDF2 from a password.

```c
sm4_get_random_iv(iv);
sm4_get_key_from_password(passwd, strlen(passwd), NULL, 0, 1024, key);
sm4_enc(sm4_cbc, key, iv, ciphertext, &clen, data, len);
sm4_dec(sm4_cbc, key, iv, plaintext, &plen, ciphertext, clen);
```