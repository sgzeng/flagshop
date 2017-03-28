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

char* SERVER_ADDR = "http://202.112.51.211:8888";

unsigned char* charxor (unsigned char *text, int len) {
    const unsigned char enc[8] = {100,125,141,111,140,129,167,133};
    int i;
    for (i = 0; i < len; i++) {
        text[i] ^= enc[i % 8];
    }
    return text;
}

/**Given a string in hex format, read it verbatim and store it in a unsigned char */
void stringToHex(unsigned char* hexString,const char* string, int stringLength)
{
    int i = 0;
    for(;i<stringLength/2;i++)
    {       
        sscanf(&string[i*2], "%02hhX", &hexString[i]);
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

int main(int argc, char const *argv[])
{   
    int length = strlen(SERVER_ADDR);
    unsigned char hexString[length];
    memcpy(hexString, SERVER_ADDR, sizeof(unsigned char)*length);
    hex_print(SERVER_ADDR, length);
    printf("\n");
    hex_print(charxor(hexString, length),length);
    printf("\n");
    hex_print(charxor(hexString, length),length);
    printf("\n");
    char *server_url = (char *)hexString;
    char hostname[15];
    memcpy(hostname, server_url+7, 14);
    hostname[14] = '\0';
    printf("hostname: %s\n", hostname);
    return 0;
}