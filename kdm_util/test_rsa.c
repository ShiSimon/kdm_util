#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "dirent.h"
#include <fcntl.h>
#include "test_rsa.h"

#define BUF_SIZE 4096
#define SMT00002_PRIKEY_ENC "SMT00002_PRIKEY_ENC"

static char prikey_enc[2048];
static int prikey_enc_len = 1696;

int setPrikey(const char * key, int keylen)
{
    if(keylen > 2048)
        return -1;
    if(keylen < 1024)
        return -2;
    memcpy(prikey_enc, key, keylen);
    prikey_enc_len = keylen;
    return 0;
}

static const uint8_t aes_key[16] = {0x71,0x99,0xE4,0x07,0x7C,0xD2,0x60,0xCB,0xF5,0xE0,0xCB,0x12,0xD5,0xF1,0x27,0x31};

/*如果文件名为一个目录,返回值为0*/
static unsigned long long get_filesize(char * fn)
{
    int fd;
    struct _stat64  buf;
    DIR  * dir;
    /*测试是否目录*/
    dir= opendir(fn);
    if(dir) {
        closedir(dir);
        return 0;
    }

    fd= _open(fn, O_RDONLY);
    if(fd== -1) {
        //perror("open");
        //fprintf(stderr,"open %s failed!\n",fn);
        return 0;
    }
    _close (fd);
    _stat64(fn, &buf);
    fflush(stdout);
    return buf.st_size;
}

#ifdef USE_MBEDTLS
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_PK_PARSE_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_MD5_C)
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md5.h"

#include <stdio.h>
#include <string.h>
#endif

#include "../aes.h"

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PK_PARSE_C) ||  \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_MD5_C)
int rsa_decrypt( const char *key_fn, unsigned char in[256], unsigned char out[256])
{
    return -1;
}

int rsa_decrypt_from_buffer( const char *buf, unsigned int len, unsigned char in[256], unsigned char out[256])
{
    return -1;
}
int get_key_buffer(char **ppbuf, unsigned int *plen, const char *keyfile)
{
    return -1;
}
#else
int rsa_decrypt( const char *key_fn, unsigned char in[256], unsigned char out[256])
{
    int ret;
    size_t olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char buf[512];
    const char *pers = "mbedtls_pk_decrypt";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    ret = 1;

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_pk_init( &pk );

    if( ( ret = mbedtls_pk_parse_keyfile( &pk, key_fn, "" ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    if( ( ret = mbedtls_pk_decrypt( &pk, in, 256, out, &olen, 256,
                            mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        goto exit;
    }

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_ERROR_C)
    if( ret != 0 )
    {
        mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
        mbedtls_printf( "  !  Last error was: %s\n", buf );
    }
#endif

    return ret ? -1 : (int)olen;
}

int rsa_decrypt_from_buffer( const char *buf, unsigned int len, unsigned char in[256], unsigned char out[256])
{
    int ret;
    size_t olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_decrypt";
    unsigned char * keybuf = NULL;
    size_t keylen = 0;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    ret = 1;

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_pk_init( &pk );


    keybuf = malloc(len + 1);
    if(keybuf == NULL)
    {
        return -1;
    }
    memcpy(keybuf, buf, len);
    keybuf[len] = '\0';
    keylen = (size_t)len;
    if( strstr( (const char *) keybuf, "-----BEGIN " ) != NULL )
        ++keylen;
    if( ( ret = mbedtls_pk_parse_key( &pk, keybuf, keylen, NULL, 0 ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    if( ( ret = mbedtls_pk_decrypt( &pk, in, 256, out, &olen, 256,
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        //mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        goto exit;
    }

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_ERROR_C)
    if( ret != 0 )
    {
        mbedtls_strerror( ret, (char *) keybuf, keylen );
        mbedtls_printf( "  !  Last error was: %s\n", keybuf );
    }
#endif
    if(keybuf) free(keybuf);
    return ret ? -1 : (int)olen;
}

static int aes_decrypt(uint8_t *in, uint8_t *out, uint32_t length, const uint8_t *key)
{
    uint8_t iv[16] = {0x5B,0x5B,0x58,0x78,0x20,0xFF,0x90,0xE4,0x22,0x66,0xC7,0x03,0xCB,0xAE,0xEA,0xE1};
    struct AVAES aesc;
    av_aes_init(&aesc, key, 128, 1);
    av_aes_crypt(&aesc, out, in, length/16, iv, 1);
    return 0;
}

/* PRIKEY_FILE -> TMP_PRIKEY_FILE 
return: 0成功 <0失败*/
int get_key_buffer(char **ppbuf, unsigned int *plen, const char *keyfile)
{
    FILE * fp_in = NULL;        /* 输入加密文件*/
    uint32_t file_size = 0;     /* 加密的文件的大小*/
    uint32_t orig_size = 0;     /* 原始文件的大小*/
    uint32_t aes_size = 0;      /* 需要解密的大小*/
    uint8_t del_size =  0;      /* 填充的大小*/
    uint8_t *buf_in = NULL;     /* 输入缓冲，包括校验值 */
    uint8_t *buf_out = NULL;    /* 解密后的buf */
    uint8_t md5[16];            /* md5校验结果 */
    uint8_t *p = NULL;
    int ret = 0;

    if(access(keyfile, F_OK) == 0)
    {            
        /* 获取信息 读取文件*/
        file_size = get_filesize((char*)keyfile);
        if(file_size < 16)
        {
            fprintf(stderr, "%s is a dir or size(%u) is not correct\n", 
                    keyfile, file_size);
            return -1;
        }
        aes_size = file_size - 16;

        buf_in = (uint8_t *)malloc(file_size);
        if(buf_in == NULL)
        {
            perror("malloc in");
            ret = -1;
            goto cleanup;
        }
        memset(buf_in, 0, file_size);
        buf_out = (uint8_t *)malloc(aes_size);
        if(buf_out == NULL)
        {
            perror("malloc out");
            ret = -1;
            goto cleanup;
        }
        memset(buf_out, 0, aes_size);

        fp_in = fopen(keyfile,"rb");
        if(fp_in == NULL)
        {
            fprintf(stderr,"cannot open %s\n",keyfile);
            ret = -1;
            goto cleanup;
        }
    
        p = buf_in;
        while(!feof(fp_in)) 
        {
            int rd = fread(p, 1, BUF_SIZE, fp_in);
            p += rd;
        }
        if( (uint32_t)(p - buf_in) != file_size)
        {
            fprintf(stderr, "read error,read num:%d\n", (int)(p-buf_in));
            ret = -1;
            goto cleanup;
        }
        else
        {
            fclose(fp_in);
            fp_in = NULL;
        }
    }
    else
    {
        file_size = prikey_enc_len;
        aes_size = file_size - 16;
        buf_in = (uint8_t *)malloc(file_size);
        if(buf_in == NULL)
        {
            perror("malloc in");
            ret = -1;
            goto cleanup;
        }
        buf_out = (uint8_t *)malloc(aes_size);
        if(buf_out == NULL)
        {
            perror("malloc out");
            ret = -1;
            goto cleanup;
        }
        memcpy(buf_in, prikey_enc, prikey_enc_len);
    }

    /* 先校验文件 */
    mbedtls_md5( (unsigned char *)buf_in, aes_size, md5);
    if(memcmp(md5, buf_in+aes_size, 16) != 0)
    {
        fprintf(stderr, "md5 is not right\n");
        ret = -1;
        goto cleanup;
    }

    /* 解密 */
    ret = aes_decrypt(buf_in, buf_out, aes_size, aes_key);
    if(ret < 0)
    {
        fprintf(stderr, "aes error\n");
        ret = -1;
        goto cleanup;
    }

    del_size = *(buf_out+aes_size-1);
    orig_size = aes_size - del_size;

    *plen = orig_size;
    *ppbuf = (char *)buf_out;

    if(0)
    {
        FILE * fpdec;
        fpdec = fopen("prikey.pem", "w");
        fwrite(*ppbuf, *plen, 1, fpdec);
        fclose(fpdec);
    }

cleanup:
    if(buf_in)
    {
        free(buf_in);buf_in = NULL;
    }

    if(ret <0 && buf_out)
    {
        free(buf_out);buf_out = NULL;
    }

    if(fp_in)
    {
        fclose(fp_in);fp_in = NULL;
    }

    return ret;
}
#endif //defined(MBEDTLS...)

#endif //defined(USE_MBEDTLS)

#ifdef USE_OPENSSL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dirent.h"
#include <errno.h>
#include <fcntl.h>
//#include <io.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ui.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#include "test_rsa.h"

#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6
#define FORMAT_ENGINE   7
#define FORMAT_IISSGC	8	/* XXX this stupid macro helps us to avoid
				 * adding yet another param to load_*key() */


#define PW_MIN_LENGTH 4
typedef struct pw_cb_data
	{
	const void *password;
	const char *prompt_info;
	} PW_CB_DATA;

static BIO *bio_err = NULL;
static UI_METHOD *ui_method = NULL;
static const char rnd_seed[] = "string to make the random number generator think it has entropy";


static int password_callback(char *buf, int bufsiz, int verify,
                      PW_CB_DATA *cb_tmp)
{
    UI *ui = NULL;
    int res = 0;
    const char *prompt_info = NULL;
    const char *password = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    if (cb_data)
    {
        if (cb_data->password)
            password = cb_data->password;
        if (cb_data->prompt_info)
            prompt_info = cb_data->prompt_info;
    }

    if (password)
    {
        res = strlen(password);
        if (res > bufsiz)
            res = bufsiz;
        memcpy(buf, password, res);
        return res;
    }

    ui = UI_new_method(ui_method);
    if (ui)
    {
        int ok = 0;
        char *buff = NULL;
        int ui_flags = 0;
        char *prompt = NULL;

        prompt = UI_construct_prompt(ui, "pass phrase",
                                     prompt_info);

        ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
        UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

        if (ok >= 0)
            ok = UI_add_input_string(ui,prompt,ui_flags,buf,
                                     PW_MIN_LENGTH,BUFSIZ-1);
        if (ok >= 0 && verify)
        {
            buff = (char *)OPENSSL_malloc(bufsiz);
            ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
                                      PW_MIN_LENGTH,BUFSIZ-1, buf);
        }
        if (ok >= 0)
            do
            {
                ok = UI_process(ui);
            }
            while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

        if (buff)
        {
            OPENSSL_cleanse(buff,(unsigned int)bufsiz);
            OPENSSL_free(buff);
        }

        if (ok >= 0)
            res = strlen(buf);
        if (ok == -1)
        {
            BIO_printf(bio_err, "User interface error\n");
            ERR_print_errors(bio_err);
            OPENSSL_cleanse(buf,(unsigned int)bufsiz);
            res = 0;
        }
        if (ok == -2)
        {
            BIO_printf(bio_err,"aborted!\n");
            OPENSSL_cleanse(buf,(unsigned int)bufsiz);
            res = 0;
        }
        UI_free(ui);
        OPENSSL_free(prompt);
    }
    return res;
}

static EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
                          const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key=NULL;
    EVP_PKEY *pkey=NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE))
    {
        BIO_printf(err,"no keyfile specified\n");
        goto end;
    }
    key=BIO_new(BIO_s_file());
    if (key == NULL)
    {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL && maybe_stdin)
    {
        setvbuf(stdin, NULL, _IONBF, 0);
        BIO_set_fp(key,stdin,BIO_NOCLOSE);
    }
    else
        if (BIO_read_filename(key,file) <= 0)
        {
            BIO_printf(err, "Error opening %s %s\n",
                       key_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    if (format == FORMAT_ASN1)
    {
        pkey=d2i_PrivateKey_bio(key, NULL);
    }
    else if (format == FORMAT_PEM)
    {
        pkey=PEM_read_bio_PrivateKey(key,NULL,
                                     (pem_password_cb *)password_callback, &cb_data);
    }
    else
    {
        BIO_printf(err,"bad input format specified for key file\n");
        goto end;
    }
end:
    if (key != NULL) BIO_free(key);
    if (pkey == NULL)
        BIO_printf(err,"unable to load %s\n", key_descrip);
    return(pkey);
}

static EVP_PKEY *load_key_from_buffer(BIO *err, const char *buf, unsigned len, int format, int maybe_stdin,
                                      const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key=NULL;
    EVP_PKEY *pkey=NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = NULL;

    if (buf == NULL && (!maybe_stdin || format == FORMAT_ENGINE))
    {
        BIO_printf(err,"no key buffer specified\n");
        goto end;
    }
    key=BIO_new(BIO_s_mem());
    if (key == NULL)
    {
        ERR_print_errors(err);
        goto end;
    }

    if (BIO_write(key,buf,len) <= 0)
    {
        BIO_printf(err, "Error write from buf %s\n",
                   key_descrip);
        ERR_print_errors(err);
        goto end;
    }

    if (format == FORMAT_ASN1)
    {
        pkey=d2i_PrivateKey_bio(key, NULL);
    }
    else if (format == FORMAT_PEM)
    {
        pkey=PEM_read_bio_PrivateKey(key,NULL,
                                     (pem_password_cb *)password_callback, &cb_data);
    }
    else
    {
        BIO_printf(err,"bad input format specified for key file\n");
        goto end;
    }
end:
    if (key != NULL) BIO_free(key);
    if (pkey == NULL)
        BIO_printf(err,"unable to load %s\n", key_descrip);
    return(pkey);
}


//int main(int argc, char* argv[])
int rsa_decrypt( const char *key_fn, unsigned char in[256], unsigned char out[256])
{
    RSA *rsa=NULL;
    BIO *output=NULL;
    int informat = FORMAT_PEM;
    ENGINE *e = NULL;
    char *passin = NULL;
    int sgckey=0;

    int ret;
    
    if(bio_err == NULL)
    {
        if((bio_err=BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);    
    }
        
    output=BIO_new(BIO_s_file());
    BIO_set_fp(output,stdout,BIO_NOCLOSE);

    {
        EVP_PKEY	*pkey;
        
        pkey = load_key(bio_err, key_fn,
                        (informat == FORMAT_NETSCAPE && sgckey ?
                         FORMAT_IISSGC : informat), 1,
                        passin, e, "Private Key");

        if (pkey != NULL)
            rsa = pkey == NULL ? NULL : EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
    }

   /*  if (!RSA_print(output,rsa,0)) */
/*     { */
/*         ERR_print_errors(bio_err); */
/*         goto cleanup; */
/*     } */

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or OAEP may fail */

    /* dec */
    {
        //fprintf(stderr, "Begin decrypt...\n");
        
        ret = RSA_private_decrypt(256, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
        if( ret < 0)
        {
            unsigned long err;
            const char *file;
            int line;
            
            err = ERR_get_error_line(&file, &line);
            if(err == 0)
            {
                fprintf(stderr, "no err at all\n");
            }
            else
            {
                fprintf(stderr, "RSA_private_decrypt:%s\n", ERR_error_string(err, NULL));
                fprintf(stderr, "err file:%s, line:%d\n", file, line);
            }
            //fprintf(stderr, "Decrypt failed!\n");
        }
        else
        {
            //fprintf(stderr, "OAEP decrypted size=%d\n", ret);
        }

    }

    if(output != NULL) BIO_free_all(output);
    if(rsa != NULL) RSA_free(rsa);

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);

    CRYPTO_mem_leaks_fp(stderr);
    return ret;
}

int rsa_decrypt_from_buffer( const char *buf, unsigned int len, unsigned char in[256], unsigned char out[256])
{
    RSA *rsa=NULL;
    BIO *output=NULL;
    int informat = FORMAT_PEM;
    ENGINE *e = NULL;
    char *passin = NULL;
    int sgckey=0;

    int ret;
    
    if(bio_err == NULL)
    {
        if((bio_err=BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);    
    }
        
    output=BIO_new(BIO_s_file());
    BIO_set_fp(output,stdout,BIO_NOCLOSE);

    {
        EVP_PKEY	*pkey;
        
        pkey = load_key_from_buffer(bio_err, buf, len, 
                                    (informat == FORMAT_NETSCAPE && sgckey ?
                                     FORMAT_IISSGC : informat), 1,
                                    passin, e, "Private Key");
        
        if (pkey != NULL)
            rsa = pkey == NULL ? NULL : EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
    }

   /*  if (!RSA_print(output,rsa,0)) */
/*     { */
/*         ERR_print_errors(bio_err); */
/*         goto cleanup; */
/*     } */

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or OAEP may fail */

    /* dec */
    {
        //fprintf(stderr, "Begin decrypt...\n");
        
        ret = RSA_private_decrypt(256, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
        if( ret < 0)
        {
            unsigned long err;
            const char *file;
            int line;
            
            err = ERR_get_error_line(&file, &line);
            if(err == 0)
            {
                fprintf(stderr, "no err at all\n");
            }
            else
            {
                fprintf(stderr, "RSA_private_decrypt:%s\n", ERR_error_string(err, NULL));
                fprintf(stderr, "err file:%s, line:%d\n", file, line);
            }
            //fprintf(stderr, "Decrypt failed!\n");
        }
        else
        {
            //fprintf(stderr, "OAEP decrypted size=%d\n", ret);
        }

    }

    if(output != NULL) BIO_free_all(output);
    if(rsa != NULL) RSA_free(rsa);

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);

    CRYPTO_mem_leaks_fp(stderr);
    return ret;
}

static int aes_decrypt(uint8_t *in, uint8_t *out, uint32_t length, const uint8_t *key)
{
    int ret = 0 ;
    AES_KEY round_key;
    uint8_t iv[16] = {0x5B,0x5B,0x58,0x78,0x20,0xFF,0x90,0xE4,0x22,0x66,0xC7,0x03,0xCB,0xAE,0xEA,0xE1};
    
    ret = AES_set_decrypt_key(key, 128, &round_key);
    if(ret < 0)return -1;
    
    AES_cbc_encrypt(in, out, length, &round_key, iv, AES_DECRYPT);
    return 0;
}

/* PRIKEY_FILE -> TMP_PRIKEY_FILE 
return: 0成功 <0失败*/
int get_key_buffer(char **ppbuf, unsigned int *plen, const char *keyfile)
{
	FILE * fp_in = NULL;        /* 输入加密文件*/
	uint32_t file_size, orig_size, aes_size;     /* 加密的文件的大小*/
	uint8_t *buf_in, *buf_out;
	//uint32_t orig_size = 0;     /* 原始文件的大小*/
	//uint32_t aes_size = 0;      /* 需要解密的大小*/
	uint8_t del_size = 0;      /* 填充的大小*/
							   //uint8_t *buf_out = NULL;    /* 解密后的buf */
	uint8_t md5[16];            /* md5校验结果 */
	uint8_t *p = NULL;
	int ret = 0;
    if(access(keyfile, 0) == 0)
    {
        /* 获取信息 读取文件*/
        file_size = get_filesize((char*)keyfile);
        if(file_size < 16)
        {
            fprintf(stderr, "%s is a dir or size(%u) is not correct\n", 
                    keyfile, file_size);
            return -1;
        }
        aes_size = file_size - 16;

        buf_in = (uint8_t *)malloc(file_size);
        if(buf_in == NULL)
        {
            perror("malloc in");
            ret = -1;
            goto cleanup;
        }
        buf_out = (uint8_t *)malloc(aes_size);
        if(buf_out == NULL)
        {
            perror("malloc out");
            ret = -1;
            goto cleanup;
        }

        fp_in = fopen(keyfile,"rb");
        if(fp_in == NULL)
        {
            fprintf(stderr,"cannot open %s\n",keyfile);
            ret = -1;
            goto cleanup;
        }
    
        p = buf_in;
        while(!feof(fp_in)) 
        {
            int rd = fread(p, 1, BUF_SIZE, fp_in);
            p += rd;
        }
        if( (uint32_t)(p - buf_in) != file_size)
        {
            fprintf(stderr, "read error,read num:%d\n", (int)(p-buf_in));
            ret = -1;
            goto cleanup;
        }
        else
        {
            fclose(fp_in);
            fp_in = NULL;
        }
    }
    else
    {
        //fprintf(stderr, "%s not exist.using SMT00002\n", keyfile);
        file_size = sizeof(SMT00002_PRIKEY_ENC);
        aes_size = file_size - 16;
        buf_in = (uint8_t *)malloc(file_size);
        if(buf_in == NULL)
        {
            perror("malloc in");
            ret = -1;
            goto cleanup;
        }
        buf_out = (uint8_t *)malloc(aes_size);
        if(buf_out == NULL)
        {
            perror("malloc out");
            ret = -1;
            goto cleanup;
        }
        memcpy(buf_in, SMT00002_PRIKEY_ENC, sizeof(SMT00002_PRIKEY_ENC));
    }

    /* 先校验文件 */
    EVP_Digest(buf_in, aes_size, md5, NULL, EVP_md5(), NULL);
//    PRINT_KEY("md5:", md5);
    if(memcmp(md5, buf_in+aes_size, 16) != 0)
    {
        fprintf(stderr, "md5 is not right\n");
        ret = -1;
        goto cleanup;
    }

    /* 解密 */
    ret = aes_decrypt(buf_in, buf_out, aes_size, aes_key);
    if(ret < 0)
    {
        fprintf(stderr, "aes error\n");
        ret = -1;
        goto cleanup;
    }

    del_size = *(buf_out+aes_size-1);
    fprintf(stderr, "del_size=%u\n", del_size);
    orig_size = aes_size - del_size;

    *plen = orig_size;
    *ppbuf = (char *)buf_out;

    if(0)
    {
        FILE * fpdec;
        fpdec = fopen("prikey.pem", "w");
        fwrite(*ppbuf, *plen, 1, fpdec);
        fclose(fpdec);
    }
    
cleanup:
    if(buf_in)
    {
        free(buf_in);buf_in = NULL;
    }

    if(ret <0 && buf_out)
    {
        free(buf_out);buf_out = NULL;
    }

    if(fp_in)
    {
        fclose(fp_in);fp_in = NULL;
    }

    return ret;
}
#endif //defined(USE_OPENSSL)

int main()
{
	return 0;
}