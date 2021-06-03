#include <stdio.h>
#include <string.h>
#include "SMx.h"
void print_hex(const byte *bin, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", bin[i]);
    putchar('\n');
}
#define N 10240
char pri[N], pub[N], out1[N], out2[N];
int main()
{
    // SM2 enc/dec
    {
        puts("---------- SM2 enc/dec ----------");
        sm2_generate_keypair(pri, pub);
        printf("prikey hex: %s\n", pri);
        printf("pubkey hex: %s\n", pub);

        const char *msg = "12345";
        printf("orig hex: ");
        print_hex(msg, strlen(msg));

        size_t olen = 0;
        sm2_enc(pub, out1, &olen, msg, strlen(msg));
        printf("enc hex: ");
        print_hex(out1, olen);

        size_t olen2 = 0;
        sm2_dec(pri, out2, &olen2, out1, olen);
        printf("dec hex: ");
        print_hex(out2, olen2);
    }
    // SM2 sign/verify
    {
        puts("---------- SM2 sign/verify ----------");
        sm2_generate_keypair(pri, pub);
        printf("prikey hex: %s\n", pri);
        printf("pubkey hex: %s\n", pub);

        const char *msg = "12345";
        printf("msg hex: ");
        print_hex(msg, strlen(msg));

        size_t olen = N; // Note that when signing message, olen must be bigger than possible result size.
        sm2_sign_msg(pri, pub, out1, &olen, msg, strlen(msg));

        printf("sig hex: ");
        print_hex(out1, olen);

        puts("verify1:");
        int r = sm2_verify_msg(pub, out1, olen, msg, strlen(msg));
        printf("result = %d\n", r);

        puts("verify2:");
        r = sm2_verify_msg(pub, out1, olen, "12344", 5);
        printf("result = %d\n", r);
    }
    // SM3 HASH/HMAC
    {
        puts("---------- SM3 HASH/HMAC ----------");
        const char *msg = "12345";
        printf("msg hex: ");
        print_hex(msg, strlen(msg));

        sm3_hash(msg, strlen(msg), out1);
        printf("hash hex: ");
        print_hex(out1, SM3_HASH_SIZE);

        sm3_hmac(msg, strlen(msg), msg, strlen(msg), out2);
        printf("hmac hex: ");
        print_hex(out2, SM3_HASH_SIZE);
    }
    // SM4 enc/dec
    {
        puts("---------- SM4 enc/dec ----------");
        const char *msg = "12345";
        const char *passwd = "12345";
        static char iv[N], key[N];
        sm4_get_random_iv(iv);
        sm4_get_key_from_password(passwd, strlen(passwd), NULL, 0, 1024, key);

        printf("msg hex: ");
        print_hex(msg, strlen(msg));

        size_t olen = 0;
        sm4_enc(sm4_cbc, key, iv, out1, &olen, msg, strlen(msg));
        printf("enc hex: ");
        print_hex(out1, olen);

        size_t olen2 = 0;
        sm4_dec(sm4_cbc, key, iv, out2, &olen2, out1, olen);

        printf("dec hex: ");
        print_hex(out2, olen2);
    }
    return 0;
}