#ifndef INCLUDED_TEST_RSA_H
#define INCLUDED_TEST_RSA_H

//#define USE_MBEDTLS
#define USE_OPENSSL

#ifdef __cplusplus
extern "C"
{
#endif

    int setPrikey(const char * key, int keylen);

    int rsa_decrypt( const char *key_fn, unsigned char in[256], unsigned char out[256]);
    int rsa_decrypt_from_buffer( const char *buf, unsigned int len, unsigned char in[256], unsigned char out[256]);

    int get_key_buffer(char **ppbuf, unsigned int *plen, const char *keyfile);

#ifdef __cplusplus
}
#endif

#endif
