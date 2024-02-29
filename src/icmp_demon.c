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

#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <pwd.h>
#include <grp.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <poll.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>

#include <getopt.h>

#include "toml.h"
#include "utils.h"

#define MAX_IP_PACKET_SIZE 65536
#define HOST_TIMEOUT 5

#define PING_TYPE_RAW         0
#define PING_TYPE_SYSTEM_32   1
#define PING_TYPE_SYSTEM_64   2
#define PING_TYPE_ALL         3

#define PING_DATA_OFFSET_32   8
#define PING_DATA_OFFSET_64  16
#define PING_DATA_OFFSET_RAW  0
#define SEQUENCE_ONLY        -1

int   verbose_level   =  LOG_WARNING;
int   use_syslog      =  0;
int   repeat_timeout  = -1;
int   run_as_daemon   =  0;
char *config_name     =  NULL;
int   ping_type       =  PING_TYPE_ALL;
char *bind_interface  =  NULL;
char *bind_address    =  NULL;

// Command-line options
static struct option long_options[] = {
        {"cfg",       required_argument, 0, 'c'},
        {"daemonize", no_argument,       0, 'd'},
        {"verbose",   required_argument, 0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0,                           0, 0}
};

typedef struct script_desc {
    char *name;
    int   content_len;
    char *content;
    char *user;
    char *group;
    char *path;
} script_desc_t;

// For timeouts
typedef struct host_record {
    uint32_t sender_ip;
    uint32_t stamp;
} host_record_t;

typedef struct config_desc {
    int            qn_scripts;
    int            qn_hosts;
    net_record_t  *host_arr;
    script_desc_t *script_arr;
} config_desc_t;

config_desc_t *cfg = NULL;

int parse_script_desc(toml_table_t* table, script_desc_t *cmd_arr, int i, const char *name) {

    int rc=-1;

    char *content_ptr = NULL;

    toml_datum_t path        = toml_string_in(table, "path");
    toml_datum_t user        = toml_string_in(table, "user");
    toml_datum_t group       = toml_string_in(table, "group");
    toml_datum_t content     = toml_string_in(table, "content");
    toml_datum_t hex_content = toml_string_in(table, "hex_content");

    if (path.ok) {
        cmd_arr[i].path=strdup((char*) path.u.s);
    }
    else {
        slog(LOG_WARNING, verbose_level, use_syslog, "Script [%s] without path! Ignore.", name);
        return rc;
    }

    if (content.ok && hex_content.ok) {
        slog(LOG_WARNING, verbose_level, use_syslog, "In the script: [%s] use content or hex_content, not both", name);
        return rc;
    }

    if (content.ok || hex_content.ok) {
        cmd_arr[i].name = strdup(name);
        if (content.ok) {
            content_ptr = strdup((char*) content.u.s);
            cmd_arr[i].content_len=strlen(content_ptr);
        }

        if (hex_content.ok) {
            int len = hex_to_string((char*) hex_content.u.s, &content_ptr);
            if (len==0) {
                slog(LOG_WARNING, verbose_level, use_syslog, "In the script: [%s] invalid hex_content [%s]", name, hex_content.u.s);
                return rc;
            }
            cmd_arr[i].content_len=len;
        }
        cmd_arr[i].content = content_ptr;
    }
    else {
        slog(LOG_WARNING, verbose_level, use_syslog, "Script [%s] without ping content! Ignore.", name);
        return rc;
    }

    if (user.ok) {
        cmd_arr[i].user=strdup((char*) user.u.s);
    }
    else {
        slog(LOG_WARNING, verbose_level, use_syslog, "User name not defined, use nobody!");
        cmd_arr[i].user=strdup("nobody");
    }

    if (group.ok) {
        cmd_arr[i].group=strdup((char*) group.u.s);
    }
    else {
        slog(LOG_WARNING, verbose_level, use_syslog, "Group name not defined, use nobody!");
        cmd_arr[i].group=strdup("nobody");
    }
    rc = 0;

    return rc;
}

int parse_config(const char *config_file, config_desc_t *config) {
    int rc=-1;
    FILE* fp;
    char errbuf[256];

    fp = fopen(config_file, "r");
    if (!fp) {
        fprintf(stderr, "Config file not found!\n");
        return rc;
    }

    toml_table_t* conf = toml_parse_file(fp, errbuf, sizeof(errbuf));

    toml_table_t* log = toml_table_in(conf, "log");
    if (log!=NULL) {
        toml_datum_t value = toml_int_in(log, "use_syslog");
        if (value.ok) {
            use_syslog = (int) value.u.i;
            slog(LOG_INFO, verbose_level, use_syslog, "Use syslog = [%d]", use_syslog);
        }
    }

    toml_table_t* network = toml_table_in(conf, "network");
    if (network!=NULL) {
        toml_datum_t value = toml_int_in(network, "repeat_timeout");
        if (value.ok) {
            repeat_timeout = (int) value.u.i;
            slog(LOG_INFO, verbose_level, use_syslog, "After script timeout = [%d]", repeat_timeout);
        }

        value = toml_string_in(network, "bind_interface");
        if (value.ok) {
            char *str_interface = (char*) value.u.s;
            // Set global variable
            bind_interface = strdup(str_interface);
        }

        value = toml_string_in(network, "bind_address");
        if (value.ok) {
            char *str_address = (char*) value.u.s;
            // Set global variable
            bind_address = strdup(str_address);
        }

        value = toml_string_in(network, "ping_type");
        if (value.ok) {
            char *str_ping_type = (char*) value.u.s;

            if (strcmp(str_ping_type, "raw")==0) {
                ping_type = PING_TYPE_RAW;
            }
            else if (strcmp(str_ping_type, "32bit")==0) {
                ping_type = PING_TYPE_SYSTEM_32;
            }
            else if (strcmp(str_ping_type, "64bit")==0) {
                ping_type = PING_TYPE_SYSTEM_64;
            }
            else if (strcmp(str_ping_type, "all")==0) {
                ping_type = PING_TYPE_ALL;
            }
            slog(LOG_INFO, verbose_level, use_syslog, "Ping type: %s", str_ping_type);
        }

        toml_array_t *host_array = toml_array_in(network, "only_from");
        if (host_array!=NULL) {
            int qn_hosts = toml_array_nelem(host_array);
            slog(LOG_INFO, verbose_level, use_syslog, "Allowed nets array exist! [%d] elems!", qn_hosts);
            net_record_t *nets = malloc(sizeof(net_record_t)*qn_hosts);
            int j=0;
            for (int i = 0; i<qn_hosts; i++) {
                toml_datum_t host = toml_string_at(host_array, i);
                if (!host.ok) {
                    break;
                }
                else {
                    uint32_t ip;
                    int prefix_len;
                    int rc = convert_IP_prefix(host.u.s, &ip, &prefix_len);
                    if (rc==0) {
                        nets[j].prefix_len=prefix_len;
                        nets[j].network_ip = ip;
                        j++;
                    }
                    else {
                        slog(LOG_WARNING, verbose_level, use_syslog, "Incorrect host specification [%s]", host.u.s);
                    }
                }
            }
            config->qn_hosts = j;
            config->host_arr = nets;
        }
    }

    toml_table_t* scripts = toml_table_in(conf, "script");
    if (scripts!=NULL) {
        slog(LOG_DEBUG, verbose_level, use_syslog, "Scripts found!");
        int i=0;
        while (1) {
            const char *key = toml_key_in(scripts, i);
            if (key==NULL) {
                break;
            }
            i++;
        }

        int keys_count=i;
        int script_count = 0;
        config->script_arr = malloc(sizeof(script_desc_t) * keys_count);

        for (int i=0; i<keys_count; i++) {
            const char *key = toml_key_in(scripts, i);
            toml_table_t* script = toml_table_in(scripts, key);
            int rc = parse_script_desc(script, config->script_arr, script_count, key);
            if (rc==0) {
                // If script desc was successfully parsed
                script_count++;
            }
        }
        config->qn_scripts = script_count;
        slog(LOG_INFO, verbose_level, use_syslog, "[%d] script desc found, [%d] correct!", keys_count, script_count);
    }

    toml_free(conf);
    fclose(fp);
    return rc;
}

void sigHandler(int signum) {
    slog(LOG_WARNING, verbose_level, use_syslog, "Got SIGINT (Ctrl+C) or SIGTERM, exit!");
    slog(LOG_WARNING, verbose_level, use_syslog, "ICMP demon finished");
    closelog();
    exit(4);
}


int start_script(const char* username, const char* groupname, const char* script_path, const char *sender_ip) {

    char command[512];

    snprintf(command, sizeof(command), "%s %s", script_path, sender_ip);

    slog(LOG_INFO, verbose_level, use_syslog, "From user: (%s/%s) start: (%s)", username, groupname, script_path);

    struct passwd *pw = getpwnam(username);
    struct group *gr  = getgrnam(groupname);

    if (pw==NULL) {
        slog(LOG_WARNING, verbose_level, use_syslog, "User [%s] not found! Cannot run script!", username);
        return -1;
    }

    if (gr==NULL) {
        slog(LOG_WARNING, verbose_level, use_syslog, "Group [%s] not found! Cannot run script!", groupname);
        return -1;
    }

    uid_t uid = pw->pw_uid;
    gid_t gid = gr->gr_gid;

    if (setgid(gid) != 0 || setuid(uid) != 0) {
        slog(LOG_WARNING, verbose_level, use_syslog, "Cannot set uid/gid");
        return -2;
    }

    if (system(command) == -1) {
        slog(LOG_WARNING, verbose_level, use_syslog,"Cannot start script");
        return -3;
    }
    return 0;
}

int Clean_host_table(Hash *h, uint32_t now, int timeout) {
    int i=0;    // Number of removed items
    for (int k = 0; k < kh_end(h); ++k) {
        if (kh_exist(h, k)) {
            host_record_t *item =(host_record_t *) kh_value(h, k);
            if (item!=NULL) {
                if ((now - item->stamp) > timeout) {
                    kh_del_m32(h, k);
                    free(item);
                    i++;
                }
            }
        }
    }
    return i;
}

int Check_host_timeout(Hash *h, uint32_t host, uint32_t now, int timeout) {
    int rc=0;
    host_record_t *hr = NULL;

    hr = Hash_Find(h, host);
    if (hr!=NULL) {
        if ((now - hr->stamp) < timeout) {
            rc = 1;       // wait for timeout
        }
        else {
            hr->stamp = now;   // timeout expired
        }
    }
    else {
        hr = (host_record_t*) malloc(sizeof(host_record_t));
        hr->sender_ip = host;
        hr->stamp = now;
        Hash_Add(h, hr->sender_ip, hr);
    }

    return rc;
}

int Get_content_offset(int ping_type) {

    int pattern_offset = 0;
    if (ping_type == PING_TYPE_SYSTEM_64) {
        pattern_offset = PING_DATA_OFFSET_64;  // 16 bytes for system ping from 64-bit host
    }
    else if (ping_type == PING_TYPE_SYSTEM_32) {
        pattern_offset = PING_DATA_OFFSET_32;  // 8 bytes for system ping from 32-bit host
    }
    else if (ping_type == PING_TYPE_RAW) {
        pattern_offset = PING_DATA_OFFSET_RAW;
    }
    return pattern_offset;
}


int Check_ping_content(char *buf, int total_len, int ping_type, char *content, int content_len) {

    int rc=-1;
    int data_len = 0;
    int offset = 0;
    int pattern_offset = 0;

    int header_offset = sizeof(struct iphdr) + sizeof(struct icmphdr);

    if (ping_type != PING_TYPE_ALL) {
        int pattern_offset = Get_content_offset(ping_type);
        offset = header_offset + pattern_offset;
        data_len = total_len - offset;
        if (data_len>=content_len) {
            offset = header_offset + pattern_offset;
            rc = strncmp(&buf[offset], content, content_len);
        }
        else {
            slog(LOG_DEBUG, verbose_level, use_syslog,  "Data len < content len [%d<%d] , ignore packet", data_len, content_len);
        }
    }
    else {
        // We should check all possible wariants
        // Start from raw ping
        pattern_offset = Get_content_offset(PING_TYPE_RAW);
        data_len = total_len - (header_offset + pattern_offset);

        if (data_len>=content_len) {
            offset = header_offset + pattern_offset;
            rc = strncmp(&buf[offset], content, content_len);
            if (rc==0) {
                return rc;
            }
        }
        else {
            // If no place for raw ping pattern - automaticaly no space for other,
            slog(LOG_DEBUG, verbose_level, use_syslog, "Data len < content len [%d<%d] , ignore raw ping packet", data_len, content_len);
            return rc;
        }

        // Next - 32-bit systems
        pattern_offset = Get_content_offset(PING_TYPE_SYSTEM_32);
        data_len = total_len - (header_offset + pattern_offset);

        if (data_len>=content_len) {
            offset = header_offset + pattern_offset;
            rc = strncmp(&buf[offset], content, content_len);
            if (rc==0) {
                return rc;
            }
        }
        else {
            // If no place for 32-bit ping pattern - automaticaly no space for 64-bit,
            slog(LOG_DEBUG, verbose_level, use_syslog,  "Data len < content len [%d<%d] , ignore 32-bit ping packet", data_len, content_len);
            return rc;
        }

        // Last - 64-bit systems
        pattern_offset = Get_content_offset(PING_TYPE_SYSTEM_64);
        data_len = total_len - (header_offset + pattern_offset);

        if (data_len>=content_len) {
            offset = header_offset + pattern_offset;
            rc = strncmp(&buf[offset], content, content_len);
            if (rc==0) {
                return rc;
            }
        }
        else {
            slog(LOG_DEBUG, verbose_level, use_syslog, "Data len < content len [%d<%d] , ignore 64-bit ping packet", data_len, content_len);
            return rc;
        }

    }
    return rc;
}


int process_socket(config_desc_t *config) {

    int i, n;

    int sockfd;
    int script_cnt = config->qn_scripts;

    struct ifreq ifr;
    socklen_t cli_len;
    script_desc_t *scripts = config->script_arr;

    struct sockaddr_in cliaddr;
    char buf[MAX_IP_PACKET_SIZE];
    struct pollfd fds[1];

    static Hash *h;

    h = Hash_New(32);
    // Signal processing
    signal(SIGINT, sigHandler);
    signal(SIGTERM, sigHandler);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        slog(LOG_ERR, verbose_level, use_syslog, "ICMP socket error! You are root?");
        exit(1);
    } else {
        slog(LOG_INFO, verbose_level, use_syslog, "ICMP socket created");
    }

    if (bind_interface != NULL) {
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), bind_interface);
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            slog(LOG_ERR, verbose_level, use_syslog, "Cannot bind socket to interface [%s]", bind_interface);
            exit(EXIT_FAILURE);
        }
        else {
            slog(LOG_INFO, verbose_level, use_syslog, "Binded on interface [%s]", bind_interface);
        }
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;

    if (bind_address!=NULL) {
        // Try to convert decimal IP to sin_addr
        inet_aton(bind_address, &bind_addr.sin_addr);
    }
    else {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Link to all addresses
    }
    if (bind(sockfd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) < 0) {
        slog(LOG_ERR, verbose_level, use_syslog, "Cannot bind socket to address [%s]", bind_address);
        exit(EXIT_FAILURE);
    }
    else {
        slog(LOG_INFO, verbose_level, use_syslog, "Binded into address [%s]", inet_ntoa(bind_addr.sin_addr));
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        slog(LOG_ERR, verbose_level, use_syslog, "Cannot set socket non-blocking mode");
        exit(EXIT_FAILURE);
    }

    cli_len = sizeof(struct sockaddr_in);

    while (1) {

        fds[0].fd = sockfd;
        fds[0].events = POLLIN;

        int pollResult = poll(fds, 1, HOST_TIMEOUT * 1000);
        if (pollResult < 0) {
            slog(LOG_ERR, verbose_level, use_syslog, "Poll error!");
            exit(EXIT_FAILURE);
        }
        else if (pollResult == 0) {
            uint32_t now = time(NULL);
            int qn_host = Clean_host_table(h, now, repeat_timeout);
            // printf("Timeout, [%d] host cleaned\n", qn_host);
            continue;
        }

        if (fds[0].revents & POLLIN) {
            n = recvfrom(sockfd, buf, MAX_IP_PACKET_SIZE, 0, (struct sockaddr *) &cliaddr, &cli_len);
            if (n <= 0) {
                slog(LOG_ERR, verbose_level, use_syslog, "recvfrom() error: %s ", strerror(errno));
                continue;
            }

            struct iphdr *ip_hdr = (struct iphdr *) buf;
            slog(LOG_DEBUG, verbose_level, use_syslog, "[%d] bytes received, IP header is %d bytes.", n, ip_hdr->ihl * 4);

            struct icmphdr *icmp_hdr = (struct icmphdr *) ((char *) ip_hdr + (4 * ip_hdr->ihl));
            slog(LOG_DEBUG, verbose_level, use_syslog, "ICMP msgtype=[%d], code=[%d]", icmp_hdr->type, icmp_hdr->code);

            if (icmp_hdr->type == ICMP_ECHO) {
                char sender_ip[INET_ADDRSTRLEN];
    
                inet_ntop(AF_INET, &(ip_hdr->saddr), sender_ip, INET_ADDRSTRLEN);
                slog(LOG_DEBUG, verbose_level, use_syslog, "Sender IP: [%s]", sender_ip);
                int rc = is_host_allowed(ip_hdr->saddr, config->host_arr, config->qn_hosts);
    
                if (rc==0) {
                    slog(LOG_WARNING, verbose_level, use_syslog, "IP [%s] not allowed, ignore packet!", sender_ip);
                    continue;
                }

                unsigned short sequence = ntohs(icmp_hdr->un.echo.sequence);
                if (repeat_timeout==SEQUENCE_ONLY) {
                    if (sequence>1) {
                        slog(LOG_DEBUG, verbose_level, use_syslog, "Ok, echo request, sequence: %d > 1, skip!", sequence);
                        continue;
                    }
                }
                else {
                    uint32_t now = time(NULL);
                    int rc=Check_host_timeout(h, ip_hdr->saddr, now, repeat_timeout);
                    if (rc==1) {
                        slog(LOG_INFO, verbose_level, use_syslog, "Command ignored during timeout!");
                        continue;
                    }
                }

                int offset = sizeof(struct iphdr) + sizeof(struct icmphdr);
                slog(LOG_DEBUG, verbose_level, use_syslog, "Content: (%d bytes) from: %d", n - offset, offset);

                /*
                for (i = offset; i < n; i++) {
                    printf("%02X%s", (uint8_t) buf[i], (i + 1) % 16 ? " " : "\n");
                }
                printf("\n");
                */

                for (i = 0; i < script_cnt; i++) {
                    int rc= Check_ping_content(buf, n, ping_type, scripts[i].content, scripts[i].content_len);
                    if (rc == 0) {
                        slog(LOG_INFO, verbose_level, use_syslog, "Ok, try to run script [%s] by request from IP:[%s]!", scripts[i].name, sender_ip);
                        start_script(scripts[i].user, scripts[i].group, scripts[i].path, sender_ip);
                    }
                    else {
                        slog(LOG_DEBUG, verbose_level, use_syslog, "Unknown content, ignore!");
                    }
                }
            }
            else {
                slog(LOG_DEBUG, verbose_level, use_syslog, "Not ICMP echo, ignore!");
            }
        }
    }

    Hash_Free(h);
    return 0;
}

int daemonize(config_desc_t *config) {
    // PID: Process ID
    // SID: Session ID
    pid_t pid, sid;
    pid = fork(); // Fork off the parent process
    if (pid < 0) {
        slog(LOG_ERR, verbose_level, use_syslog, "Exit failure!");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    // Create a SID for child
    sid = setsid();
    if (sid < 0) {
        // FAIL
        slog(LOG_ERR, verbose_level, use_syslog, "Failure in setsid()!");
        exit(EXIT_FAILURE);
    }
    if ((chdir("/")) < 0) {
        // FAIL
        slog(LOG_ERR, verbose_level, use_syslog, "Failure in chdir()!");
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    process_socket(config);

    exit(EXIT_SUCCESS);
}

int parse_options(int argc, char **argv) {
    int rc = 0;
    char *str_verb;
    int c;
    while ((c = getopt_long(argc, argv, "c:v:dh", long_options, NULL)) != -1) {
        switch (c) {
            case 'c':
                config_name = strdup(optarg);
                break;
            case 'v':
                str_verb = strdup(optarg);
                if (strcmp(str_verb, "info")==0) {
                    verbose_level = LOG_INFO;
                }
                else if (strcmp(str_verb, "error")==0) {
                    verbose_level = LOG_ERR;
                }
                else if (strcmp(str_verb, "warning")==0) {
                    verbose_level = LOG_WARNING;
                }
                else if (strcmp(str_verb, "debug")==0) {
                    verbose_level = LOG_DEBUG;
                }
                break;
            case 'd':
                run_as_daemon = 1;
                break;
            case 'h':
                printf("Usage:\n    icmp_demon -c <cfg file> -v {error|warning|info|debug} [-d] [-h]\n");
                return 1;
                break;
            case '?':
                printf("So, what?");
                return 2;
                break;
            default:
                // Unknown errors
                rc = 13;
                break;
        }
    }
    return rc;
}

int main(int argc, char **argv) {

    int rc = parse_options(argc, argv);
    if (rc!=0) {
        return rc;
    }

    if (config_name==NULL) {
        fprintf(stderr, "Have no config file, exit!\n");
        exit(3);
    }
    else {
        cfg = malloc(sizeof(config_desc_t));
        memset(cfg, 0, sizeof(config_desc_t));
        parse_config(config_name, cfg);
    }

    openlog("icmp-demon", LOG_PID, LOG_USER);
    slog(LOG_WARNING, verbose_level, use_syslog, "ICMP demon started");

    if (run_as_daemon == 0) {
        process_socket(cfg);
    }
    else {
        daemonize(cfg);
    }

    printf("Normal exit!\n");
    closelog();
}
