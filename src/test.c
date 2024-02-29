#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int isIpAddressValid(uint32_t ipAddress, uint32_t allowedAddress, int maskLength) {
    uint32_t mask = 0xFFFFFFFF << (32 - maskLength);
    return (ipAddress & mask) == (allowedAddress & mask);
}


int convertIpAndPrefix(const char* ipPrefix, uint32_t* ipAddress, int* prefixLength) {

    int  rc=-1;
    char ip[20];          // Min len: 1.1.1.1, Max len: 222.222.222.222/31
    int slashIndex = -1;

    memset(ip, 0, sizeof(ip));

    int len = strlen(ipPrefix);

    if (len<7 || len>18) {
        return rc;
    }

    for (int i=0;i<len;i++) {
        if (ipPrefix[i]=='/') {
            slashIndex = i;
            ip[i] = 0;
        }
        else {
            ip[i] = ipPrefix[i];
        }
    }

    if (slashIndex==-1) {
        // No slash, pure IP addr
        *prefixLength = 32;
    }
    else {
        *prefixLength = atoi(&ipPrefix[slashIndex + 1]);
    }
    
    if (*prefixLength < 1 || *prefixLength > 32) {
        return rc;
    }

    *ipAddress=inet_addr(ip);

    return rc;
}

int main(int argc, char **argv) {
    const char hexstring[] = "DEadbeef10203040b00b1e50", *pos = hexstring;
    unsigned char val[12];

     /* WARNING: no sanitization or error-checking whatsoever */
    for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }

    printf("0x");
    for(size_t count = 0; count < sizeof val/sizeof *val; count++)
        printf("%02x", val[count]);
    printf("\n");

    return 0;
}
