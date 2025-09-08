/* The MIT License

   Copyright (c) 2023 by Andrew Jelly (ajelly@gmail.com)

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

*/

#include <stdarg.h>
#include "utils.h"

kh_m32_t *Hash_New(int initial_size) {
    return kh_init(m32);
}

void Hash_Free(khash_t(m32) *h) {
    kh_destroy(m32, h);
}

int Hash_Add(khash_t(m32) *h, int key, void *value) {
    int ret;
    khiter_t k=0;
    {
        k = kh_put(m32, h, key, &ret);
        kh_value(h, k) = value;
    }
    return k;
}

int Hash_SoftAdd(khash_t(m32) *h, int key, void *value) {
    int ret;
    khiter_t k=0;

    {
        k = kh_put(m32, h, key, &ret);
        kh_value(h, k) = value;
    }

    return k;
}

void *Hash_Find(khash_t(m32) *h, int key) {

    khiter_t k=0;
    void *value;

    {
        k = kh_get(m32, h, key);
        if (k!= kh_end(h)) {
            value=kh_value(h, k);
        }
        else {
            value=NULL;
        }
    }
    return value;
}

void Hash_Delete(khash_t(m32) *h, int key) {

    khiter_t k=0;
    
    {
        k = kh_get(m32, h, key);
        kh_del(m32, h, k);
    }
}

void slog(int priority, int verbose_level, int use_syslog, const char* format, ...) {
    va_list args;
    char buffer[1024];

    if (priority>verbose_level) {
        // No log
        return;
    }

    va_start(args, format);

    vsnprintf(buffer, sizeof(buffer), format, args);
    printf("%s\n", buffer);
    if (use_syslog==1) {
        syslog(priority, "%s", buffer);
    }

    va_end(args);
}

int hex_to_string(const char *value, char **result) {

    char *buffer;
    const char *pos = value;
    int length = strlen(value);

    if (length%2!=0) {
        // Half byte?
        return 0;
    }
    else {
        buffer = malloc(1+length/2);
        memset(buffer, 0, 1+length/2);
    }

    // TODO: Rewrite, may be later
    for (size_t count = 0; count < length/2; count++) {
        sscanf(pos, "%2hhx", &buffer[count]);
        pos += 2;
    }

    *result = buffer;
    return length/2;
}

int is_IP_valid(uint32_t ipAddress, uint32_t allowedAddress, int maskLength) {
    // Check if IP valid (network order!)
    uint32_t mask = 0xFFFFFFFF >> (32 - maskLength);
    return (ipAddress & mask) == (allowedAddress & mask);
}

int is_host_allowed(uint32_t host, net_record_t *nets, int qn_nets) {
    int rc=0;
    if (qn_nets==0) {
        // Empty only_from list
        return 1;
    }

    for (int i=0;i<qn_nets;i++) {
        // printf("Check [%08X] against [%08X/%d]\n", host,nets[i].network_ip, nets[i].prefix_len);
        rc = is_IP_valid(host, nets[i].network_ip, nets[i].prefix_len);
        if (rc==1) {
            break;
        }
    }
    return rc;
}

int convert_IP_prefix(const char* ipPrefix, uint32_t *ipAddress, int *prefixLength) {

    int  rc=-1;
    char ip[20];          // Min len: 1.1.1.1, Max len: 222.222.222.222/31
    int  slashIndex = -1;

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

    return 0;
}

long get_monotonic_time() {

    long rc=0;
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        rc=ts.tv_sec;
    }
    else {
        perror("Cannot get monotonic time!\n");
        return 1;
    }

    return rc;
}
