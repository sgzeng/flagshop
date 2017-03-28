#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>
#include "error.h"

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
#define PUB_KEYLEN 65

char* SERVER_HOST_NAME = "202.112.51.211";
// char* SERVER_HOST_NAME = "127.0.0.1";
int SERVER_HOST_PORT_NO = 8080;
int client_socket;

/*Nice little macro to save a few lines.*/
void die(char *reason)
{
    fprintf(stderr, reason);
    fflush(stderr);
    exit(1);
}

unsigned char* charxor(unsigned char *text, int len) {
	const unsigned char enc[12] = {'s', 'n', 'o', 'w', 'b', 'o', 'a', 'r', 'd', 'i', 'n', 'g'};
    int i;
    for (i = 0; i < len; i++) {
        text[i] ^= enc[i % 12];
    }
    return text;
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

bool verify(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    char mac[MAC_LENGTH*2+1];
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&mac[i*2], "%02x", (unsigned int)m[i]);
    // printf("verify: HMAC of ***%s*** using ",msg);
    // hex_print(key, keylen);
    // printf(" as key is %s\n", mac);
    if(!strncmp(signature,mac,MAC_LENGTH*2)){
        return true;
    }else{
        return false;
    }
}

void sign(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&signature[i*2], "%02x", (unsigned int)m[i]);
    // printf("exp sign: HMAC of %s is %s\n",msg,signature);
}

static char *rand_string(char *str, size_t size)
{
    srand ( time(NULL) );
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    if (size) {
        --size;
        size_t n = 0;
        for(; n < size; n++) {
            int key = rand() % 25;
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

char* getname(size_t size)
{
     char *s = malloc(size + 1);
     if (s) {
         rand_string(s, size);
     }
     return s;
}

void connecttoserver(){
	struct sockaddr_in client_addr;
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = INADDR_ANY;
	client_addr.sin_port = htons(0);
	
	//create a socket
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(client_socket < 0 )
	{
		fail("create client socket fail");
	}
	
	struct sockaddr_in server_addr;
	bzero((char *)&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;

	struct hostent *server;
	server = gethostbyname(SERVER_HOST_NAME);
	if(server == NULL)
	{
		fail("fail to get host name");
	}
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);

	server_addr.sin_port = htons(atoi("8080"));
	socklen_t server_addr_len = sizeof(server_addr);

 	//printf("connecting to %s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), server_addr.sin_port);
	if(connect(client_socket, (struct sockaddr*) &server_addr, server_addr_len) == -1 )
	{
		fail("connent to shop server fail");
	}
}

void sendtoserver(char *msg){
	char* content = msg;
	send(client_socket, content, strlen(content), 0);
	//printf("send completed, size = %d\n", strlen(content));
	
}

void sendtoclient(char *msg, int client_socket){
	char* content = msg;
	send(client_socket, content, strlen(content), 0);
	//printf("send completed, size = %d\n", strlen(content));
	
}

int recvfromserver(char *msg){
	char buffer_received[1024];
	memset(buffer_received, '\0', 1024);
	int length_received = recv(client_socket, buffer_received, sizeof(buffer_received), 0);
	if(length_received < 0)
	{
		fail("receive fail");
	}
	//printf("get bytes length: %d\n", length_received);
	buffer_received[length_received] = '\0';
	//printf("%s\r\n", buffer_received);
	memcpy(msg,buffer_received,sizeof(char)*length_received);
	return length_received;
}

int recvfromserveruntil(char *msg){
	char buffer_received[512];
	memset(buffer_received, '\0', sizeof(char)*512);
	int length_received=0;
	while(length_received < 512){
		recv(client_socket, buffer_received+length_received, 1, 0);
		//printf("Received: %s length_received: %d\n", buffer_received, length_received);
		length_received++;
		if(length_received > 11 && !strncmp((buffer_received+length_received-11),"signature: ",11)){
			break;
		}
	}
	length_received -= 11;
	//buffer_received[length_received] = '\0';
	memcpy(msg,buffer_received,sizeof(char)*length_received);
	//printf("Received: ***%s*** length_received: %d\n", msg, length_received);
	return length_received;
}

int connecttoshop(){
	struct sockaddr_in client_addr;
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = INADDR_ANY;
	client_addr.sin_port = htons(0);
	
	//create a socket
	int shop_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(shop_socket < 0 )
	{
		fail("create client socket fail");
	}
	
	struct sockaddr_in server_addr;
	bzero((char *)&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;

	struct hostent *server;
	server = gethostbyname(SERVER_HOST_NAME);
	if(server == NULL)
	{
		fail("fail to get wallet host name");
	}
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);

	server_addr.sin_port = htons(atoi("3344"));
	socklen_t server_addr_len = sizeof(server_addr);

 	//printf("connecting to %s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), server_addr.sin_port);
	if(connect(shop_socket, (struct sockaddr*) &server_addr, server_addr_len) == -1 )
	{
		fail("connent to wallet server fail");
	}
	return shop_socket;
}

void exp(unsigned char* lSecret, int lSecretLen, char *username){

	int i;
	int shop_socket = connecttoshop();
	char t[16];
	time_t time_now = time(NULL);
	sprintf(t, "%ld", time_now);
	char *s1 = "\n";
	char *s2 = "accept";
	char *s3 = username;
	char *s4 = t;
	char *s5 = "signature: ";
	char *s6 = "c";
	unsigned char* pSecret = malloc(sizeof(unsigned char)*lSecretLen);
	memcpy(pSecret,lSecret, sizeof(unsigned char)*lSecretLen);
	charxor(pSecret, lSecretLen);
	char s7[lSecretLen*2+1];
	memset(s7, '\0', sizeof(unsigned char)*(lSecretLen*2+1));
	for(i=0;i<lSecretLen;i++)
		sprintf(&s7[i*2], "%02X", (unsigned int)pSecret[i]);
	char str[512];
	memset(str, '\0', sizeof(char)*512);
	strcat(str, s6);
	strcat(str, s1);
	strcat(str, s2);
	strcat(str, s1);
	strcat(str, s3);
	strcat(str, s1);
	strcat(str, s4);
	strcat(str, s1);
	strcat(str, s7);
	strcat(str, s5);
	char signature[128];
	memset(signature, '\0', 128);
	sign(str, lSecret, lSecretLen, signature);
	strcat(str, signature);
	//printf("str sending to the shop: %s\n", str);
	sendtoclient(str,shop_socket);
}


int main()
{
	setbuf(stdin,0);
	setbuf(stdout,0);
	connecttoserver();
	int i;
	char *username = getname(10);

	puts("  (b) get flag for hello kitty");
	puts("  (c) get flag for dummy shop");
	printf("Username: %s\n", username);
	printf("Now tell me what do you want to buy(a/b): ");
	char choice[2];
	choice[1] = '\0';
	read(0, choice, 1);
	if(!strncmp(choice,"b",1)){
		sendtoserver(username);
		sendtoserver("\n");
		sendtoserver("b");
		sendtoserver("\n");
		char t[16];
		time_t timestamp = time(NULL);
		sprintf(t, "%ld", timestamp);
		sendtoserver(t);
		sendtoserver("\n");

		/* ECDH key exchange*/
	    EC_KEY *lKey;
	    int lSecretLen;
	    unsigned char *lSecret;
	    lKey = gen_key();
	    
	    /* client serialize the public key:*/
	    BN_CTX *bnctx = BN_CTX_new();
	    if ((bnctx) == NULL)
	        die("BN_CTX_new failed\n");
	    size_t pubkeylen = EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	    unsigned char* buffer = malloc(sizeof(unsigned char) * pubkeylen);
	    if (EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, buffer, pubkeylen, bnctx) != pubkeylen) {
	        die("EC_POINT_point2oct length mismatch\n");
	    }
	    //convert the shared lsecret to string in hex format
	    char shared_key[pubkeylen*2+1];
	    shared_key[pubkeylen*2] = '\0';
		for(i=0;i<pubkeylen;i++)
			sprintf(&shared_key[i*2], "%02X", (unsigned int)buffer[i]);	

		// printf("lshared_key from client: %s\n", shared_key);
	    sendtoserver(shared_key);
	    memset(buffer, 0, sizeof(unsigned char)*pubkeylen);
	    memset(shared_key, '\0', sizeof(char)*(pubkeylen*2+1));	

	    recvfromserver(shared_key);
	    // printf("pshared_key from shop: %s\n", shared_key);	

	    /* client deserialize the public key:*/
	    stringToHex(buffer, shared_key, pubkeylen*2);
	    EC_POINT *pkey_pub = EC_POINT_new(EC_KEY_get0_group(lKey));
	    if (EC_POINT_oct2point(EC_KEY_get0_group(lKey), pkey_pub, buffer, pubkeylen, bnctx) != 1) {
	        die("buffer_get_bignum2_ret: BN_bin2bn failed\n");
	    }	

	    // shop and client compute the shared key
	    lSecretLen = EC_DH(&lSecret, lKey, pkey_pub);

		char kitty[512];
		memset(kitty,'\0',sizeof(char)*512);
		char signature[128];
		memset(signature,'\0',sizeof(char)*128);
		memset(signature, '\0', 128);
		memset(kitty, '\0', sizeof(char)*512);
		recvfromserveruntil(kitty);
		recvfromserver(signature);
		char message[1024];
		memset(message,'\0',sizeof(char)*1024);
		strcat(message, kitty);
		strcat(message, "signature: ");
		if(verify(message, lSecret, lSecretLen, signature)){
			printf("%s\n", kitty);
		}else{
			puts("Fake kitty received!");
		}
		// printf("%s\n", kitty);

		close(client_socket);
	}
	else if(!strncmp(choice,"c",1)){

		sendtoserver(username);
		sendtoserver("\n");
		sendtoserver(choice);
		sendtoserver("\n");
		char t[16];
		time_t timestamp = time(NULL);
		sprintf(t, "%ld", timestamp);
		sendtoserver(t);
		sendtoserver("\n");

		/* ECDH key exchange*/
	    EC_KEY *lKey;
	    int lSecretLen;
	    unsigned char *lSecret;
	    lKey = gen_key();
	    
	    /* client serialize the public key:*/
	    BN_CTX *bnctx = BN_CTX_new();
	    if ((bnctx) == NULL)
	        die("BN_CTX_new failed\n");
	    size_t pubkeylen = EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	    unsigned char* buffer = malloc(sizeof(unsigned char) * pubkeylen);
	    if (EC_POINT_point2oct(EC_KEY_get0_group(lKey), EC_KEY_get0_public_key(lKey), POINT_CONVERSION_UNCOMPRESSED, buffer, pubkeylen, bnctx) != pubkeylen) {
	        die("EC_POINT_point2oct length mismatch\n");
	    }
	    //convert the shared lsecret to string in hex format
	    char shared_key[pubkeylen*2+1];
	    shared_key[pubkeylen*2] = '\0';
		for(i=0;i<pubkeylen;i++)
			sprintf(&shared_key[i*2], "%02X", (unsigned int)buffer[i]);	

		// printf("lshared_key from client: %s\n", shared_key);
	    sendtoserver(shared_key);
	    memset(buffer, 0, sizeof(unsigned char)*pubkeylen);
	    memset(shared_key, '\0', sizeof(char)*(pubkeylen*2+1));	

	    recvfromserver(shared_key);
	    // printf("pshared_key from shop: %s\n", shared_key);	

	    /* client deserialize the public key:*/
	    stringToHex(buffer, shared_key, pubkeylen*2);
	    EC_POINT *pkey_pub = EC_POINT_new(EC_KEY_get0_group(lKey));
	    if (EC_POINT_oct2point(EC_KEY_get0_group(lKey), pkey_pub, buffer, pubkeylen, bnctx) != 1) {
	        die("buffer_get_bignum2_ret: BN_bin2bn failed\n");
	    }	

	    // shop and client compute the shared key
	    lSecretLen = EC_DH(&lSecret, lKey, pkey_pub);
	   
	    exp(lSecret, lSecretLen, username);

		char kitty[512];
		char signature[128];
		memset(signature, '\0', 128);
		memset(kitty, '\0', sizeof(char)*512);
		recvfromserveruntil(kitty);
		recvfromserver(signature);
	    // shop and client compute the shared key
	    lSecretLen = EC_DH(&lSecret, lKey, pkey_pub);
	    // printf("ECDH shared key: ");
	    // hex_print(lSecret, lSecretLen);
		char message[1024];
		memset(message,'\0',1024);
		strcat(message, kitty);
		strcat(message, "signature: ");
		// if(verify(message, lSecret, lSecretLen, signature)){
		// 	printf("%s\n", kitty);
		// }else{
		// 	puts("Fake kitty received!");
		// }
		printf("%s\n", kitty);

		close(client_socket);
	}
	else{
		puts("Invaid input!");
	}
	puts("bye~");
	return 0;
}
