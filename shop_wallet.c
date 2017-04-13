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
#define PUB_KEYLEN 32

int PORT_NO = 6666;


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
    //printf("sign: HMAC of %s is %s\n",msg,signature);
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
	server = gethostbyname("127.0.0.1");
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

void sendtoclient(char *msg, int client_socket){
	char* content = msg;
	send(client_socket, content, strlen(content), 0);
	//printf("send completed, size = %d\n", strlen(content));
	
}

int recvfromclient(char *option, int client_socket){
	char buffer_received[1024];
	memset(buffer_received, '\0', sizeof(char)*1024);
	int length_received = recv(client_socket, buffer_received, sizeof(buffer_received), 0);
	if(length_received < 0)
	{
		fail("receive fail");
	}
	//printf("get bytes length: %d\n", length_received);
	//buffer_received[length_received] = '\0';
	//printf("Received: %s\nlength_received: %d\n", buffer_received, length_received);
	memcpy(option,buffer_received,sizeof(char)*length_received);
	return length_received;
}

int recvuntil(char *msg, int client_socket){
	char buffer_received[512];
	memset(buffer_received, '\0', sizeof(char)*512);
	int length_received=0;
	char c = '\0';
	while(length_received < 512 && c != '\n'){
		recv(client_socket, buffer_received+length_received, 1, 0);
		//printf("Received: %s length_received: %d\n", buffer_received, length_received);
		c = buffer_received[length_received];
		length_received++;
	}
	buffer_received[length_received-1] = '\0';
	memcpy(msg,buffer_received,sizeof(char)*length_received);
	//printf("Received: ***%s***\n", msg);
	return length_received;
}

int recvfromshopuntil(char *msg, int shop_socket){
	char buffer_received[512];
	memset(buffer_received, '\0', sizeof(char)*512);
	int length_received=0;
	while(length_received < 512){
		recv(shop_socket, buffer_received+length_received, 1, 0);
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

 void mythread(int *shopsocket){
 	int new_server_socket = *shopsocket;
	if(new_server_socket < 0)
	{
		close(new_server_socket);
		puts("accept fail");
		return;
	}
	//printf("accept client %s\n", inet_ntoa(client_addr.sin_addr));
	char username[11], option[2], timestamp[16], money[5], key[PUB_KEYLEN*2+1];
	if(recvuntil(username, new_server_socket) > 11){
		close(new_server_socket);
		puts("invaid username input");
		return;
	}
	if(recvuntil(option, new_server_socket) > 2){
		close(new_server_socket);
		puts("invaid option input");
		return;
	}
	if(recvuntil(timestamp, new_server_socket) > 16){
		close(new_server_socket);
		puts("invaid timestamp input");
		return;
	}
	if(recvuntil(money, new_server_socket) > 5){
		close(new_server_socket);
		puts("invaid money input");
		return;
	}
	printf("client %s want to buy %s.\n", username, option);
	recvfromshopuntil(key, new_server_socket);
	unsigned char *Secret = malloc(sizeof(unsigned char)*PUB_KEYLEN);
	stringToHex(Secret, key, PUB_KEYLEN*2);
	// printf("xored secret: ");
	// hex_print(Secret, PUB_KEYLEN);
	charxor(Secret, PUB_KEYLEN);
	// printf("shared secret: ");
	// hex_print(Secret, PUB_KEYLEN);
	char signature[MAC_LENGTH*2+1];
	memset(signature, '\0', sizeof(char)*(MAC_LENGTH*2+1));
	recvfromclient(signature, new_server_socket);
	//printf("username: ***%s*** \n option: ***%s*** \n money: ***%s*** \n signature: ***%s*** \n", username, option, money, signature);
	close(new_server_socket);
	char c = option[0];
	if(c == 'b'){
	    int shop_socket = connecttoshop();
		char t[16];
		time_t time_now = time(NULL);
		sprintf(t, "%ld", time_now);
		char *s1 = "\n";
		char *s2 = "accept";
		char *s3 = username;
		char *s4 = t;
		char *s5 = "signature: ";
		char *s6 = option;
		char *s7 = key;
		// memset(s7,'\0', sizeof(unsigned char)*(PUB_KEYLEN*2+1));
		int i;
		// for(i=0;i<PUB_KEYLEN;i++)
		// 	sprintf(&s7[i*2], "%02X", (unsigned int)Secret[i]);
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

		memset(signature, '\0', sizeof(char)*(MAC_LENGTH*2+1));
		sign(str, Secret, PUB_KEYLEN, signature);
		strcat(str, signature);

		//printf("str sending to the shop: %s\n", str);
		sendtoclient(str,shop_socket);
		close(shop_socket);

	}else if(c == 'c'){
		sleep(2);
	    int shop_socket = connecttoshop();
		char t[16];
		time_t time_now = time(NULL);
		sprintf(t, "%ld", time_now);
		char *s1 = "\n";
		char *s2 = "reject";
		char *s3 = username;
		char *s4 = t;
		char *s5 = "signature: ";
		char *s6 = option;
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
		strcat(str, key);
		strcat(str, s5);
		//printf("str sending to the shop: %s\n", str);
		memset(signature, '\0', sizeof(char)*(MAC_LENGTH*2+1));
		sign(str, Secret, PUB_KEYLEN, signature);
		strcat(str, signature);
		sendtoclient(str,shop_socket);
		close(shop_socket);
	}else{
                return;
		//sendtoclient("Invaid input!\n",shop_socket);
	}

 }

 int main(){
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

	struct hostent *server;
	server = gethostbyname("127.0.0.1");
	if(server == NULL)
	{
		fail("fail to get host name");
	}
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);

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

	printf("the server started...\n");
	//printf("listening: addr=%s, port=%d\n", inet_ntoa(server_addr.sin_addr.s_addr), port_no);

	//printf("waiting for client...\n");
	
	socklen_t length = sizeof(struct sockaddr_in);

	while(1)
	{
		int s = accept(socket_fd, (struct sockaddr *) &client_addr, &length);
		int *arg = malloc(sizeof(*arg));
		if(arg == NULL){
			fail("Couldn't allocate memory for thread arg.");
		}
		*arg = s;
		pthread_t thread_id;
		if(pthread_create(&thread_id, NULL, (void *) mythread, arg) != 0){
			fail("Create pthread error!");
		}
		//pthread_join(id,NULL);
	}
	return 0;
}

