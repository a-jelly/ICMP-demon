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

#ifndef utils_h
#define utils_h

#include <inttypes.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <arpa/inet.h>

#include "khash.h"

#ifdef __cplusplus
extern "C" {
#endif

KHASH_MAP_INIT_INT(m32, void*)

#define Hash kh_m32_t

// For admin restrictions
typedef struct net_record {
    uint32_t network_ip;
    int      prefix_len;
} net_record_t;

// Hash specific
kh_m32_t *Hash_New(int initial_size);
int       Hash_Add(khash_t(m32) *h, int key, void *value);
void      Hash_Free(khash_t(m32) *h);
int       Hash_SoftAdd(khash_t(m32) *h, int key, void *value);
void     *Hash_Find(khash_t(m32) *h, int key);
void      Hash_Delete(khash_t(m32) *h, int key);

// Parsing and other
void      slog(int priority, int verbose_level, int use_syslog, const char* format, ...);
int       hex_to_string(const char *value, char **result);
int       is_IP_valid(uint32_t ipAddress, uint32_t allowedAddress, int maskLength);
int       is_host_allowed(uint32_t host, net_record_t *nets, int qn_nets);
int       convert_IP_prefix(const char* ipPrefix, uint32_t *ipAddress, int *prefixLength);

#ifdef __cplusplus
}
#endif

#endif
