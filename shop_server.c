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
#include <pthread.h>
#include <arpa/inet.h>
#include "error.h"
#include "dictionary.h"

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

#define dic_SIZE 500
#define PUB_KEYLEN 32
#define MAC_LENGTH 20

int PORT_NO = 8080;
int RES_PORT_NO = 3344;
Dictionary *dictionary;
pthread_mutex_t mutex;

/*Nice little macro to save a few lines.*/
void die(char *reason)
{
    fprintf(stderr, reason);
    fflush(stderr);
    exit(1);
}

unsigned char* charxor (unsigned char *text, int len) {
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

void sign(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&signature[i*2], "%02x", (unsigned int)m[i]);
    // printf("sign: HMAC of ***%s*** using ",msg);
    // hex_print(key, keylen);
    // printf(" as key is %s\n", signature);
}

bool verify(const char* msg, unsigned char* key, int keylen, char* signature){
    //Calculate mac_j=HMAC(k_j,c_j)
    int i;
    char mac[MAC_LENGTH*2+1];
    unsigned char* m = HMAC(EVP_sha1(),key,keylen,msg,strlen(msg),NULL,NULL);
    for(i=0;i<MAC_LENGTH;i++)
        sprintf(&mac[i*2], "%02x", (unsigned int)m[i]);
    // printf("verify: received HMAC is %s\n",mac);
    // printf("verify: computed HMAC is %s\n",signature);
    if(!strncmp(signature,mac,MAC_LENGTH*2)){
        return true;
    }else{
        return false;
    }
}

void sendtoclient(char *msg, int client_socket){
	char* content = msg;
	send(client_socket, content, strlen(content), 0);
	//printf("send completed, size = %d\n", strlen(content));
	
}

int connecttowallet(){
	struct sockaddr_in client_addr;
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = INADDR_ANY;
	client_addr.sin_port = htons(0);
	
	//create a socket
	int wallet_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(wallet_socket < 0 )
	{
		fail("create client socket fail");
	}
	
	struct sockaddr_in server_addr;
	bzero((char *)&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;

	struct hostent *server;
	server = gethostbyname("127.0.0.1");
	if(server == NULL)
	{
		fail("fail to get wallet host name");
	}
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);

	server_addr.sin_port = htons(atoi("6666"));
	socklen_t server_addr_len = sizeof(server_addr);

 	//printf("connecting to %s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), server_addr.sin_port);
	if(connect(wallet_socket, (struct sockaddr*) &server_addr, server_addr_len) == -1 )
	{
		fail("connent to wallet server fail");
	}
	return wallet_socket;
}

void sendtowallet(char *msg, int wallet_socket){
	char* content = msg;
	send(wallet_socket, content, strlen(content), 0);
	//printf("send completed, size = %d\n", strlen(content));
	
}

int recvfromclient(char *msg, int msglen, int client_socket){
	char buffer_received[1024];
	memset(buffer_received, '\0', sizeof(char)*1024);
	int length_received = recv(client_socket, buffer_received, sizeof(buffer_received), 0);
	if(length_received < 0)
	{
		fail("receive fail");
	}
	// printf("get bytes length: %d\n", length_received);
	buffer_received[length_received] = '\0';
	//printf("Received: ***%s***\n", buffer_received);
	if(length_received < msglen){
		memcpy(msg,buffer_received,sizeof(char)*length_received);
	}
	return length_received;
}

int recvuntil(char *msg, int msglen, int client_socket){
	char buffer_received[512];
	memset(buffer_received, '\0', sizeof(char)*512);
	int length_received=0;
	char c = '\0';
	while(length_received < 512 && c != '\n'){
		recv(client_socket, buffer_received+length_received, 1, 0);
		// printf("Received: %s length_received: %d\n", buffer_received, length_received);
		c = buffer_received[length_received];
		length_received++;
	}
	if(length_received < msglen){
		buffer_received[length_received-1] = '\0';
		memcpy(msg,buffer_received,sizeof(char)*length_received);
	}
	//printf("Received: ***%s***\n", msg);
	return length_received;
}

int recvfromwallet(char *msg, int msglen, int wallet_socket){
	char buffer_received[1024];
	memset(buffer_received, '\0', 1024);
	int length_received = recv(wallet_socket, buffer_received, sizeof(buffer_received), 0);
	if(length_received < 0)
	{
		fail("receive fail");
	}
	if(length_received < msglen){
		memcpy(msg,buffer_received,sizeof(char)*length_received);
	}
	return length_received;
}

int recvfromwalletuntil(char *msg, int msglen, int wallet_socket){
	char buffer_received[512];
	memset(buffer_received, '\0', sizeof(char)*512);
	int length_received=0;
	while(length_received < 512){
		recv(wallet_socket, buffer_received+length_received, 1, 0);
		//printf("Received: %s length_received: %d\n", buffer_received, length_received);
		length_received++;
		if(length_received > 11 && !strncmp((buffer_received+length_received-11),"signature: ",11)){
			break;
		}
	}
	length_received -= 11;
	//buffer_received[length_received] = '\0';
	if(length_received < msglen){
		memcpy(msg,buffer_received,sizeof(char)*length_received);
	}
	//printf("Received: ***%s*** length_received: %d\n", msg, length_received);
	return length_received;
}

 void res_thread(){
    int socket_fd, client_fd, port_no;
    char buffer[256];
    struct sockaddr_in server_addr, client_addr;

    //create a socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if( socket_fd < 0){
    	fail("create socket fail");
    }

	//configure the server
	port_no = PORT_NO;
	bzero((char *)&server_addr, sizeof(server_addr));	

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(RES_PORT_NO);

	int opt = 1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if(bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0)
	{
		fail("bind socket fail");
	}

	//listen the socket
	if(listen(socket_fd, 500))
	{
		fail("listen socket fail");
	}

	printf("the response server started...\n");
	//printf("listening: addr=%s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), port_no);
	//printf("waiting for client...\n");
	socklen_t length = sizeof(struct sockaddr_in);

	while(1)
	{
		int wallet_socket = accept(socket_fd, (struct sockaddr *) &client_addr, &length);
		char option[3], username[11], response[10], timestampw[16], key[PUB_KEYLEN*2+1];
		if(recvuntil(option, 3, wallet_socket) > 3){
			close(wallet_socket);
			puts("invaid option");
			continue;
		}
		if(recvuntil(response, 10, wallet_socket) > 10){
			close(wallet_socket);
			puts("invaid response");
			continue;
		}
		if(recvuntil(username, 11, wallet_socket) > 10){
			close(wallet_socket);
			puts("invaid username");
			continue;
		}
		if(recvuntil(timestampw, 16, wallet_socket) > 16){
			close(wallet_socket);
			puts("invaid timestampw");
			continue;
		}
		recvfromwalletuntil(key, PUB_KEYLEN*2+1, wallet_socket);
		printf("%s %s\n",username,response);

		char signature[128];
		memset(signature, '\0', 128);
		recvfromwallet(signature, 128, wallet_socket);
		// pthread_mutex_lock(&mutex); 
		int client_socket = dictionary_search(dictionary, username);
		if(client_socket == -1){
			sleep(1);
			client_socket = dictionary_search(dictionary, username);
			if(client_socket == -1){
				close(wallet_socket);
				// pthread_mutex_unlock(&mutex);
				continue;
			}
		}
		dictionary_delete(dictionary, username);
		// pthread_mutex_unlock(&mutex);
		char message[512];
		memset(message, '\0', sizeof(char)*512);
		strcat(message, option);
		strcat(message, "\n");
		strcat(message, response);
		strcat(message, "\n");
		strcat(message, username);
		strcat(message, "\n");
		strcat(message, timestampw);
		strcat(message, "\n");
		strcat(message, key);
		strcat(message, "signature: ");
		unsigned char *Secret = malloc(sizeof(unsigned char)*PUB_KEYLEN);
		memset(Secret, 0, sizeof(unsigned char)*PUB_KEYLEN);
		stringToHex(Secret, key, PUB_KEYLEN*2);
		// printf("xored secret: ");
		// hex_print(Secret, PUB_KEYLEN);
		charxor(Secret, PUB_KEYLEN);
		// printf("shared secret: ");
		// hex_print(Secret, PUB_KEYLEN);
		// printf("receiced msg from wallet: %s\n", message);
		if(verify(message, Secret, PUB_KEYLEN, signature)){

			char kitty[1024], resp[1024];
			memset(signature, '\0', 128);
			memset(kitty, '\0', 1024);
			memset(resp, '\0', 1024);
			if(option[0]=='b' && !strncmp(response,"accept",6) ){
				char *flag = "bctf{3854a2d204433f9843e364d89fff500b}signature: ";
				sign(flag, Secret, PUB_KEYLEN, signature);
				strcat(resp, flag);
				strcat(resp, signature);
				//printf("response: ***%s***\nwallet time: ***%s***\nsignature: ***%s***\n", response, timestampw, signature);
				sendtoclient(resp, client_socket);
			}else if(option[0]=='c' && !strncmp(response,"accept",6) ){
				char *flag = "bctf{0af9e55648a4cab8ac97648a5d0b7059}signature: ";
				sign(flag, Secret, PUB_KEYLEN, signature);
				strcat(resp, flag);
				strcat(resp, signature);
				//printf("response: ***%s***\nwallet time: ***%s***\nsignature: ***%s***\n", response, timestampw, signature);
				sendtoclient(resp, client_socket);
			}
			else{
				char *error_msg = "smart retailer: I'v checked your wallet. $10 cannot buy flag, no way to cheat!signature: null";
				sendtoclient(error_msg, client_socket);
			}
		}else{
			char *hint_msg = "The past shopping experience tells me that xor makes my secret safe...signature: you are very close :)";
			sendtoclient(hint_msg, client_socket);

		}
		close(client_socket);
	}
 }

 void forward_thread(int *socket){
 	int new_server_socket = *socket;
	if(new_server_socket < 0)
	{
		puts("accept fail");
		return;
	}

	char username[11], option[3], timestamp[12];
	if(recvuntil(username, 11, new_server_socket) > 11){
		close(new_server_socket);
		puts("invaid username input");
		return;
	}
	if(recvuntil(option, 3, new_server_socket) > 2){
		close(new_server_socket);
		puts("invaid option input");
		return;
	}
	if(recvuntil(timestamp, 12, new_server_socket) > 12){
		close(new_server_socket);
		puts("invaid timestamp input");
		return;
	}
	printf("client %s want to buy %s.\n", username, option);

	char *money;
	if(option[0]=='b'){
		money = "$10";
	}else if(option[0]=='c'){
		money = "$999";
	}
	else{
		close(new_server_socket);
		puts("invaid option input");
		return;
	}

	/* ECDH key exchange*/
	char pshared_key[131];
    pshared_key[130] = '\0';
    BN_CTX *bnctx = BN_CTX_new();
    int i;
	/* ECDH key exchange*/
    EC_KEY *pKey;
    int pSecretLen;
    pKey = gen_key();
    unsigned char *pSecret;
	char lshared_key[131];
    lshared_key[130] = '\0';
	if(recvfromclient(lshared_key, 131, new_server_socket) > 131){
		close(new_server_socket);
		puts("invaid lshared_key");
		return;	
	}
	//printf("lshared_key from client: %s\n", lshared_key);
	/* shop deserialize the public key:*/
	unsigned char* lpub_key = malloc(sizeof(unsigned char) * 65);
    stringToHex(lpub_key, lshared_key, 65*2);

    EC_POINT *lkey_pub = EC_POINT_new(EC_KEY_get0_group(pKey));
    if (EC_POINT_oct2point(EC_KEY_get0_group(pKey), lkey_pub, lpub_key, 65, bnctx) != 1) {
        die("buffer_get_bignum2_ret: BN_bin2bn failed\n");
    }

    
    /* client serialize the public key:*/
    if ((bnctx) == NULL)
        die("BN_CTX_new failed\n");
    size_t pubkeylen = EC_POINT_point2oct(EC_KEY_get0_group(pKey), EC_KEY_get0_public_key(pKey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
    unsigned char* buffer = malloc(sizeof(unsigned char) * pubkeylen);
    if (EC_POINT_point2oct(EC_KEY_get0_group(pKey), EC_KEY_get0_public_key(pKey), POINT_CONVERSION_UNCOMPRESSED, buffer, pubkeylen, bnctx) != pubkeylen) {
        die("EC_POINT_point2oct length mismatch\n");
    }
    //convert the shared psecret to string in hex format
	for(i=0;i<pubkeylen;i++)
		sprintf(&pshared_key[i*2], "%02X", (unsigned int)buffer[i]);
	//printf("pshared_key from shop: %s\n", pshared_key);
    sendtoclient(pshared_key, new_server_socket);

    // shop and client compute the shared key
    pSecretLen = EC_DH(&pSecret, pKey, lkey_pub);
	// printf("shared secret: ");
	// hex_print(pSecret, pSecretLen);
	unsigned char *lSecret = malloc(sizeof(unsigned char)*pSecretLen);
	memcpy(lSecret, pSecret, sizeof(unsigned char)*pSecretLen);
	charxor(pSecret, pSecretLen);
	char s7[pSecretLen*2+1];
	memset(s7, '\0', sizeof(unsigned char)*(pSecretLen*2+1));
	for(i=0;i<pSecretLen;i++)
		sprintf(&s7[i*2], "%02X", (unsigned int)pSecret[i]);	
	// printf("xored secret: %s", s7);
	int wallet_socket = connecttowallet();
	char t[16];
	time_t time_now = time(NULL);
	sprintf(t, "%ld", time_now);
	char *s1 = "\n";
	char *s2 = username;
	char *s3 = option;
	char *s4 = t;
	char *s5 = money;
	char *s6 = "signature: ";
	char str[512];
	memset(str, '\0', sizeof(char)*512);
	strcat(str, s2);
	strcat(str, s1);
	strcat(str, s3);
	strcat(str, s1);
	strcat(str, s4);
	strcat(str, s1);
	strcat(str, s5);
	strcat(str, s1);
	strcat(str, s7);
	strcat(str, s6);
	char signature[MAC_LENGTH*2+1];
	signature[MAC_LENGTH*2] = '\0';
	sign(str, lSecret, pSecretLen, signature);
	strcat(str, signature);
	// printf("str sending to the wallet: %s\n", str);
	pthread_mutex_lock(&mutex); 
	if(dictionary_search(dictionary, username) == -1){
		dictionary_insert(dictionary, username, new_server_socket);
	}else{
		close(wallet_socket);
		pthread_mutex_unlock(&mutex);
		return;
	}
	pthread_mutex_unlock(&mutex);
	sendtowallet(str, wallet_socket);
	close(wallet_socket);
 }

 int main(){
 	pthread_mutex_init(&mutex,NULL);
 	dictionary = dictionary_create(dic_SIZE);
	setbuf(stdin,0);
	setbuf(stdout,0);
    int socket_fd, client_fd, port_no;
    char buffer[256];
    struct sockaddr_in server_addr, client_addr;

    //create a socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if( socket_fd < 0){
    	fail("create socket fail");
    }

	//configure the server
	port_no = PORT_NO;
	bzero((char *)&server_addr, sizeof(server_addr));	

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port_no);

	int opt = 1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if(bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0)
	{
		fail("bind socket fail");
	}

	//listen the socket
	if(listen(socket_fd, 500))
	{
		fail("listen socket fail");
	}

	printf("the forward server started...\n");
	//printf("listening: addr=%s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), port_no);
	//printf("waiting for client...\n");
	socklen_t length = sizeof(struct sockaddr_in);
	
	pthread_t rthread_id;
	if(pthread_create(&rthread_id, NULL, (void *) res_thread, NULL) != 0){
		fail("Create pthread error!");
	}

	while(1)
	{
		int s = accept(socket_fd, (struct sockaddr *) &client_addr, &length);
		int *arg = malloc(sizeof(*arg));
		if(arg == NULL){
			fail("Couldn't allocate memory for thread arg.");
		}
		*arg = s;
		pthread_t fthread_id;
		if(pthread_create(&fthread_id, NULL, (void *) forward_thread, arg) != 0){
			fail("Create pthread error!");
		}
		//pthread_join(id,NULL);
	}
	return 0;
}

