#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/ecdh.h>
/*NID_X9_62_prime256v1*/
#include <openssl/evp.h>
#include <sys/types.h>

#include <openssl/bn.h>

#define MAC_LENGTH 20
#define CIPHER_LENGTH 20
#define dbg 0

/*Nice little macro to save a few lines.*/
void die(char *reason)
{
    fprintf(stderr, reason);
    fflush(stderr);
    exit(1);
}

/*Elliptic Curve Diffie-Hellman function*/
int EC_DH(unsigned char **secret, EC_KEY *key, const EC_POINT *pPub)
{
    int secretLen;

    secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secretLen = (secretLen + 7) / 8;
    *secret = malloc(secretLen);
    memset(*secret,0,secretLen);
    if (!(*secret))
        die("Failed to allocate memory for secret.\n");
    //printf("Secret before: %X\n",*secret);
    secretLen = ECDH_compute_key(*secret, secretLen, pPub, key, NULL);
    //printf("Secret after: %X\n",*secret);
    //printf("Secretlen: %d\n",secretLen);
    return secretLen;
}

/*Key generation function for throwaway keys.*/
EC_KEY* gen_key(void)
{
    EC_KEY *key;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        die("Failed to create lKey object.\n");

    if (!EC_KEY_generate_key(key))
        die("Failed to generate EC key.\n");

    return key;
}

/**Given a string in hex format, read it verbatim and store it in a unsigned char */
void stringToHex(unsigned char* hexString,const char* string, int stringLength)
{
    int i = 0;
    for(;i<stringLength/2;i++)
    {       
        sscanf(&string[2*i], "%02hhX", &hexString[i]);
    }
}

/**Gien a unsigned char data and its length, print it out in hex format*/
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X", *p++);
    }
    printf("\n");
}

void sign(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&signature[i*2], "%02x", (unsigned int)m[i]);
    //printf("sign: HMAC of %s is %s\n",msg,signature);
}

bool verify(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    char mac[MAC_LENGTH*2+1];
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&mac[i*2], "%02x", (unsigned int)m[i]);
    printf("verify: received HMAC is %s\n",mac);
    printf("verify: computed HMAC is %s\n",signature);
    if(!strncmp(signature,mac,MAC_LENGTH*2)){
        return true;
    }else{
        return false;
    }
}

int main(int argc, char **argv)
{
    setbuf(stdin,0);
    setbuf(stdout,0);
    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;
    lKey = gen_key();
    pKey = gen_key();

    // shop and client exchange the ecdh pub_key
    
    /* client serialize the public key:*/
    BN_CTX *bnctx = BN_CTX_new();
    if ((bnctx) == NULL)
        die("BN_CTX_new failed\n");
    size_t pubkeylen = EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
    printf("pubkeylen: %d\n", pubkeylen);
    unsigned char* buffer = malloc(sizeof(unsigned char) * pubkeylen);
    if (EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, buffer, pubkeylen, bnctx) != pubkeylen) {
        die("EC_POINT_point2oct length mismatch\n");
    }

    /* shop deserialize the public key:*/
    EC_POINT *lkey_pub = EC_POINT_new(EC_KEY_get0_group(pKey));
    if (EC_POINT_oct2point(EC_KEY_get0_group(pKey), lkey_pub, buffer, pubkeylen, bnctx) != 1) {
        die("buffer_get_bignum2_ret: BN_bin2bn failed\n");
    }
    // shop and client compute the shared key
    lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
    pSecretLen = EC_DH(&pSecret, pKey, lkey_pub);
    if(lSecretLen == -1 && pSecretLen == -1){
        die("Failed to compute the secret\n");
    }
    // lSecret = malloc(sizeof(unsigned char)*lSecretLen);
    // memcpy(lSecret, lSecret_buffer, sizeof(unsigned char)*lSecretLen);
    // pSecret = malloc(sizeof(unsigned char)*pSecretLen);
    // memcpy(pSecret, pSecret_buffer, sizeof(unsigned char)*pSecretLen);
    // hex_print(lSecret, lSecretLen);
    // hex_print(pSecret, pSecretLen);

    // shop send the shared key to wallet and forward the msg
    char *message = "Hello world!";
    char signature[MAC_LENGTH*2+1];
    int i;
    signature[MAC_LENGTH*2] = '\0';
    sign(message, pSecret, pSecretLen, signature);

    if(verify(message, lSecret, lSecretLen, signature)){
        puts("Authentication OK");
    }else{
        puts("Authentication failed");
    }
    
    // shop verify and send the data to client

    free(lSecret);
    free(pSecret);
    EC_KEY_free(lKey);
    EC_KEY_free(pKey);
    CRYPTO_cleanup_all_ex_data();
    
    return 0;
}