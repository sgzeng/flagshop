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

const unsigned char SERVER_URL[21] = {0x0C, 0x09, 0xF9, 0x1F, 0xB6, 0xAE, 0x88, 0xB7, 0x54, 0x4F, 0xA3, 0x5E, 0xBD, 0xB3, 0x89, 0xB0, 0x55, 0x53, 0xBF, 0x5E, 0xBD, 0xBB, 0x9F, 0xBD, 0x5C, 0x45};
 int SERVER_HOST_PORT_NO = 8080;
int client_socket;

/*Nice little macro to save a few lines.*/
void die(char *reason)
{
    fprintf(stderr, reason);
    fflush(stderr);
    exit(1);
}

void charxor(char *hostname, unsigned char *text, int len) {
    const unsigned char enc[8] = {100,125,141,111,140,129,167,133};
    int i;
    for (i = 0; i < len; i++) {
        text[i] ^= enc[i % 8];
    }
    memcpy(hostname, text+7, 14);
    hostname[14] = '\0';
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
    // printf("verify: computed shared secret is ");
    // hex_print(key, keylen);
    // printf("received: ***%s***\n", msg);
    // printf("verify: computed HMAC is ***%s***\n",mac);
    // printf("verify: received HMAC is ***%s***\n",signature);
    if(!strncmp(signature,mac,MAC_LENGTH*2)){
        return true;
    }else{
        return false;
    }
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
	int length = 21;
    unsigned char hexString[length];
    memcpy(hexString, SERVER_URL, sizeof(unsigned char)*length);
    char hostname[15];
    charxor(hostname, hexString, length);
	server = gethostbyname(hostname);
	// server = gethostbyname("127.0.0.1");

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

 void get_kitty(char* kitty){
 	char *s1="\n/＼＿＿╭╭╭╭╭＿＿＿／\\  \n";
 	char *s2="│＼＿＿╭╭╭╭╭＿＿＿／│  \n";
 	char *s3="│　　　　　　　　　 │  \n";
 	char *s4="│　　　　　　　　 　│  \n";
 	char *s5="│　＞　　　　　●　  │  \n";
 	char *s6="│　≡　　╰┬┬┬╯  ≡    │ \n";
 	char *s7="│　　　　╰—╯　　　  │  \n";
 	char *s8="╰—————┬ｏ—ｏ┬———————╯ \n";
 	char *s9="　　　│Kitty│-       \n";
 	char *s10="　　　╰┬———┬╯        \n";
 	char buffer[512];
 	memset(buffer, '\0', sizeof(char)*512);
 	strcat(buffer,s1);
 	strcat(buffer,s2);
 	strcat(buffer,s3);
 	strcat(buffer,s4);
 	strcat(buffer,s5);
 	strcat(buffer,s6);
 	strcat(buffer,s7);
 	strcat(buffer,s8);
 	strcat(buffer,s9);
 	strcat(buffer,s10);
 	memcpy(kitty, buffer, sizeof(char)*strlen(buffer));
 }

int main(int argc, char ** argv)
{
	setbuf(stdin,0);
	setbuf(stdout,0);
	connecttoserver();
	int i;
	char *username = getname(10);
	char choice[2];
	choice[1] = '\0';
	if(argc==1){
		puts("Welcome to the shop! Your balance is $10, have fun~\n");
		puts("  (a) hello kitty                   $10");
		puts("  (b) flag of hello kitty           $10");
		puts("  (c) flag of dummy shop            $999");
		puts("  (d) flag of babySQL               FREE");
		printf("Now tell me what do you want to buy(a/b): ");
		read(0, choice, 1);
		printf("transcation id: %s\n", username);
	}else if(argc==2){
		choice[0] = argv[1][0];
	}
	if(!strncmp(choice,"a",1)){
		char kitty[1024];
		memset(kitty, '\0', 1024);
		get_kitty(kitty);
		printf("%s", kitty);
	}
	else if(!strncmp(choice,"d",1)){
		puts("BCTF{8572160a2bc7743ad02b539f74c24917}");
	}
	else if(!strncmp(choice,"b",1)){
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

	    /* client deserialize the public key:*/
	    stringToHex(buffer, shared_key, pubkeylen*2);
	    EC_POINT *pkey_pub = EC_POINT_new(EC_KEY_get0_group(lKey));
	    if (EC_POINT_oct2point(EC_KEY_get0_group(lKey), pkey_pub, buffer, pubkeylen, bnctx) != 1) {
	        die("buffer_get_bignum2_ret: BN_bin2bn failed\n");
	    }	
		char kitty[512];
		char *signature = "sth to be checked";
		memset(kitty, '\0', sizeof(char)*512);
		recvfromserver(kitty);
	    // shop and client compute the shared key
	    lSecretLen = EC_DH(&lSecret, lKey, pkey_pub);
	    // printf("ECDH shared key: ");
	    // hex_print(lSecret, lSecretLen);
		char message[512];
		memset(message,'\0',512);
		strcat(message, kitty);
		if(verify(message, lSecret, lSecretLen, signature)){
			puts("purchase completed...");
		}else{
			puts("cargo inspection failed...");
		}
		close(client_socket);
	}
	else if(!strncmp(choice,"c",1)){
		puts("lazy retailer: You only have $10, I know it!");
	}
	else{
		puts("Invaid input!");
	}
	return 0;
}
