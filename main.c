#include <noise/protocol.h>
#include "echo-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>

#define short_options "k:vf"
#define SERVER_PORT (50000)

#define max(a,b) (((a) > (b)) ? (a) : (b))
#define min(a,b) (((a) < (b)) ? (a) : (b))


typedef
struct session_t {
    int initialized;
    int ping;

    int session_soc;
    int service_soc;

    struct session_t* prev;
    struct session_t* next;
} SESSION;

typedef
struct session_list_t {
    SESSION* head;
    SESSION* tail;
} SESSION_LIST;

enum {
    PKT_HANDSHAKE = 0,
    PKT_PING,
    PKT_DATA
};

enum {
    PARSE_None = 0,
    PARSE_Cmd,
    PARSE_Len_0,
    PARSE_Len_1,
    PARSE_Len_2,
    PARSE_Len_3,
    PARSE_Payload
};

typedef unsigned int 	UINT32;
typedef unsigned short 	UINT16;
typedef unsigned char	UINT8;
typedef int 		INT32;
typedef short		INT16;
typedef char		INT8;

typedef
struct SERVER_PACKET {
    UINT8 cmd;
    UINT32 len;
    UINT32 recv;
    char* payload;
}SERVER_PACKET;

SESSION_LIST g_session_list;
pthread_mutex_t g_session_list_mutex;

#define LOCK_SESSION_LIST do { \
    pthread_mutex_lock(&g_session_list_mutex); \
} while(0)

#define UNLOCK_SESSION_LIST do { \
    pthread_mutex_unlock(&g_session_list_mutex); \
} while(0)

static struct option const long_options[] = {
    {"key-dir",                 required_argument,      NULL,       'k'},
    {"verbose",                 no_argument,            NULL,       'v'},
    {"fixed-ephemeral",         no_argument,            NULL,       'f'},
    {NULL,                      0,                      NULL,        0 }
};

/* Parsed command-line options */
static const char* key_dir = "./key";
static int fixed_ephemeral = 0;

/* Loaded keys */
#define CURVE25519_KEY_LEN 32
#define CURVE448_KEY_LEN 56
static uint8_t g_client_key_25519[CURVE25519_KEY_LEN];
static uint8_t g_server_key_25519[CURVE25519_KEY_LEN];
static uint8_t g_client_key_448[CURVE448_KEY_LEN];
static uint8_t g_server_key_448[CURVE448_KEY_LEN];
static uint8_t psk[32];

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 65535

/* Curve25519 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_25519[32] = {
    0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
    0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
    0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
    0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
};

/* Curve448 private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_448[56] = {
    0x3f, 0xac, 0xf7, 0x50, 0x3e, 0xbe, 0xe2, 0x52,
    0x46, 0x56, 0x89, 0xf1, 0xd4, 0xe3, 0xb1, 0xdd,
    0x21, 0x96, 0x39, 0xef, 0x9d, 0xe4, 0xff, 0xd6,
    0x04, 0x9d, 0x6d, 0x71, 0xa0, 0xf6, 0x21, 0x26,
    0x84, 0x0f, 0xeb, 0xb9, 0x90, 0x42, 0x42, 0x1c,
    0xe1, 0x2a, 0xf6, 0x62, 0x6d, 0x98, 0xd9, 0x17,
    0x02, 0x60, 0x39, 0x0f, 0xbc, 0x83, 0x99, 0xa5
};

/* New Hope private key to use when fixed ephemeral mode is selected */
static uint8_t const fixed_ephemeral_newhope[32] = {
    0xba, 0xc5, 0xba, 0x88, 0x1d, 0xd3, 0x5c, 0x59,
    0x71, 0x96, 0x70, 0x00, 0x46, 0x92, 0xd6, 0x75,
    0xb8, 0x3c, 0x98, 0xdb, 0x6a, 0x0e, 0x55, 0x80,
    0x0b, 0xaf, 0xeb, 0x7e, 0x70, 0x49, 0x1b, 0xf4
};

/* Print usage information */
static void usage(const char* progname)
{
    fprintf(stderr, "Usage: %s [options]\n\n", progname);
    fprintf(stderr, "Options:\n\n");
    fprintf(stderr, "    --key-dir=directory, -k directory\n");
    fprintf(stderr, "        Directory containing the client and server keys.\n\n");
}

/* Parse the command-line options */
static int parse_options(int argc, char* argv[])
{
    const char* progname = argv[0];
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'k':   key_dir = optarg; break;
        default:
            usage(progname);
            return 0;
        }
    }
    if ((optind + 1) != argc) {
        usage(progname);
        return 0;
    }
    return 1;
}



void init_session_list() {
    g_session_list.head = 0;
    g_session_list.tail = 0;
    pthread_mutex_init(&g_session_list_mutex, 0);
}

SESSION* insert_session(int session_soc) {
    SESSION* s = (SESSION*)malloc(sizeof(SESSION));
    memset(s, 0, sizeof(SESSION));

    s->initialized = 0;
    s->ping = 0;
    s->session_soc = session_soc;
    s->service_soc = -1;
    s->prev = 0;
    s->next = 0;

    LOCK_SESSION_LIST;
    if (g_session_list.tail) {
        g_session_list.tail->next = s;
        s->prev = g_session_list.tail;
        g_session_list.tail = s;
    }
    else {
        g_session_list.head = s;
        g_session_list.tail = s;
    }
    UNLOCK_SESSION_LIST;
    return s;
}

char* build_handleshake_pkt(char* host, UINT16 port, int* pkt_len) {
    int payload_len = strlen(host) + 1 + sizeof(port);
    int len = sizeof(char) + sizeof(int) + payload_len;
    char* buf = (char*)malloc(len);
    memset(buf, 0, len);
    int offset = 0;

    buf[0] = PKT_HANDSHAKE; offset += sizeof(char);
    buf[1] = (payload_len & 0x000000FF);
    buf[2] = ((payload_len & 0x0000FF00) >> 8);
    buf[3] = ((payload_len & 0x00FF0000) >> 16);
    buf[4] = ((payload_len & 0xFF000000) >> 24);
    offset += sizeof(int);

    strcpy(buf + offset, host);
    offset += strlen(host);
    offset++;
    buf[offset++] = (port & 0x00FF);
    buf[offset++] = ((port & 0xFF00) >> 8);
    *pkt_len = len;
    return buf;
}

char* build_ping_pkt(int* pkt_len) {
    int len = sizeof(char) + sizeof(int);
    char* buf = (char*)malloc(len);
    memset(buf, 0, len);
    buf[0] = PKT_PING;
    *pkt_len = len;
    return buf;
}

char* build_data_pkt(char* data, int data_len, int* pkt_len) {
    int len = sizeof(char) + sizeof(int) + data_len;
    char* buf = (char*)malloc(len);
    memset(buf, 0, len);
    int offset = 0;

    buf[0] = PKT_DATA; offset += sizeof(char);
    buf[1] = (data_len & 0x000000FF);
    buf[2] = ((data_len & 0x0000FF00) >> 8);
    buf[3] = ((data_len & 0x00FF0000) >> 16);
    buf[4] = ((data_len & 0xFF000000) >> 24);
    offset += sizeof(int);

    memcpy(buf + offset, data, data_len);
    *pkt_len = len;
    return buf;
}

void remove_session(SESSION* s) {
    printf("remove\n");
    LOCK_SESSION_LIST;
    SESSION* e = g_session_list.head;
    while (e) {
        if (e == s) {
            SESSION* prev = s->prev;
            SESSION* next = s->next;
            if (prev) {
                prev->next = next;
            }
            else {
                g_session_list.head = next;
            }

            if (next) {
                next->prev = s->prev;
            }
            else {
                g_session_list.tail = prev;
            }
            free(s);
            break;
        }
    }
    UNLOCK_SESSION_LIST;
    printf("<--remove \n");
}

/* Set a fixed ephemeral key for testing */
static int set_fixed_ephemeral(NoiseDHState* dh)
{
    if (!dh)
        return NOISE_ERROR_NONE;
    if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE25519) {
        return noise_dhstate_set_keypair_private
        (dh, fixed_ephemeral_25519, sizeof(fixed_ephemeral_25519));
    }
    else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_CURVE448) {
        return noise_dhstate_set_keypair_private
        (dh, fixed_ephemeral_448, sizeof(fixed_ephemeral_448));
    }
    else if (noise_dhstate_get_dh_id(dh) == NOISE_DH_NEWHOPE) {
        return noise_dhstate_set_keypair_private
        (dh, fixed_ephemeral_newhope, sizeof(fixed_ephemeral_newhope));
    }
    else {
        return NOISE_ERROR_UNKNOWN_ID;
    }
}

/* Initializes the handshake with all necessary keys */
static int initialize_handshake
(NoiseHandshakeState* handshake, const NoiseProtocolId* nid,
    const void* prologue, size_t prologue_len)
{
    NoiseDHState* dh;
    int dh_id;
    int err;

    /* Set the prologue first */
    err = noise_handshakestate_set_prologue(handshake, prologue, prologue_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("prologue", err);
        return 0;
    }

    /* Set the PSK if one is needed */
    if (nid->prefix_id == NOISE_PREFIX_PSK) {
        err = noise_handshakestate_set_pre_shared_key
        (handshake, psk, sizeof(psk));
        if (err != NOISE_ERROR_NONE) {
            noise_perror("psk", err);
            return 0;
        }
    }

    /* Set the local keypair for the server based on the DH algorithm */
    if (noise_handshakestate_needs_local_keypair(handshake)) {
        dh = noise_handshakestate_get_local_keypair_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_keypair_private
            (dh, g_server_key_25519, sizeof(g_server_key_25519));
        }
        else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_keypair_private
            (dh, g_server_key_448, sizeof(g_server_key_448));
        }
        else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set server private key", err);
            return 0;
        }
    }

    /* Set the remote public key for the client */
    if (noise_handshakestate_needs_remote_public_key(handshake)) {
        dh = noise_handshakestate_get_remote_public_key_dh(handshake);
        dh_id = noise_dhstate_get_dh_id(dh);
        if (dh_id == NOISE_DH_CURVE25519) {
            err = noise_dhstate_set_public_key
            (dh, g_client_key_25519, sizeof(g_client_key_25519));
        }
        else if (dh_id == NOISE_DH_CURVE448) {
            err = noise_dhstate_set_public_key
            (dh, g_client_key_448, sizeof(g_client_key_448));
        }
        else {
            err = NOISE_ERROR_UNKNOWN_ID;
        }
        if (err != NOISE_ERROR_NONE) {
            noise_perror("set client public key", err);
            return 0;
        }
    }

    /* Set the fixed local ephemeral value if necessary */
    if (fixed_ephemeral) {
        dh = noise_handshakestate_get_fixed_ephemeral_dh(handshake);
        err = set_fixed_ephemeral(dh);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("fixed ephemeral value", err);
            return 0;
        }
        dh = noise_handshakestate_get_fixed_hybrid_dh(handshake);
        err = set_fixed_ephemeral(dh);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("fixed ephemeral hybrid value", err);
            return 0;
        }
    }

    /* Ready to go */
    return 1;
}


void* accept_th(void*);
void* session_th(void*);
int main(int argc, char* argv[])
{
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 0;
    }

    if (chdir(key_dir) < 0) {
        perror(key_dir);
        return 0;
    }
    if (!echo_load_private_key("server_key_25519", g_server_key_25519, sizeof(g_server_key_25519))) {
        return 0;
    }
    if (!echo_load_private_key("server_key_448", g_server_key_448, sizeof(g_server_key_448))) {
        return 0;
    }
    if (!echo_load_public_key("client_key_25519.pub", g_client_key_25519, sizeof(g_client_key_25519))) {
        return 0;
    }
    if (!echo_load_public_key("client_key_448.pub", g_client_key_448, sizeof(g_client_key_448))) {
        return 0;
    }

    init_session_list();
    pthread_t tid;
    pthread_create(&tid, 0, accept_th, 0);
    pthread_join(tid, 0);

    return 0;
}

void* accept_th(void* arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[8192] = { 0 };
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        printf("failed to create server socket\n");
        return 0;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        printf("failed to bind, %s, %d\n", strerror(errno), errno);
        return 0;
    }

    if (listen(server_fd, 16) < 0) {
        printf("failed to listen\n");
        return 0;
    }

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            printf("failed to accept\n");
            return 0;
        }
        SESSION* s = insert_session(new_socket);
        pthread_t tid;
        pthread_create(&tid, 0, session_th, (void*)s);
    }
    return 0;
}

int my_send(int b, char* buf, int len) {
    int offset = 0;
    while (offset < len) {
        int n = send(b, buf + offset, len - offset, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                sleep(1);
                continue;
            }
            return -1;
        }
        offset += n;
    }
    return 0;
}


#define SEND_VIA_NOISE do { \
    noise_buffer_set_inout(mbuf, message + 2, buf_len, sizeof(message) - 2); \
    err = noise_cipherstate_encrypt(send_cipher, &mbuf); \
    if (err != NOISE_ERROR_NONE) { \
        noise_perror("write", err); \
        goto END_TH; \
    } \
    message[0] = (uint8_t)(mbuf.size >> 8); \
    message[1] = (uint8_t)mbuf.size; \
    if (!echo_send(s->session_soc, message, mbuf.size + 2)) { \
        goto END_TH; \
    } \
} while(0)

void* session_th(void* arg) {
    SESSION* s = (SESSION*)arg;
    int cp;

    NoiseHandshakeState* handshake = 0;
    NoiseCipherState* send_cipher = 0;
    NoiseCipherState* recv_cipher = 0;
    EchoProtocolId id;
    NoiseProtocolId nid;
    NoiseBuffer mbuf;
    size_t message_size;
    uint8_t message[MAX_MESSAGE_LEN + 2];
    int err;
    int ok = 1;
    int action;

    if (ok && !echo_recv_exact(s->session_soc, (uint8_t*)&id, sizeof(id))) {
        printf("Did not receive the echo protocol identifier\n");
        ok = 0;
    }
    if (ok && !echo_to_noise_protocol_id(&nid, &id)) {
        printf("Unknown echo protocol identifier\n");
        ok = 0;
    }
    if (ok) {
        err = noise_handshakestate_new_by_id(&handshake, &nid, NOISE_ROLE_RESPONDER);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("create handshake", err);
            ok = 0;
        }
    }
    if (ok) {
        if (!initialize_handshake(handshake, &nid, &id, sizeof(id))) {
            ok = 0;
        }
    }
    if (ok) {
        err = noise_handshakestate_start(handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("start handshake", err);
            ok = 0;
        }
    }
    while (ok) {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            message[0] = (uint8_t)(mbuf.size >> 8);
            message[1] = (uint8_t)mbuf.size;
            if (!echo_send(s->session_soc, message, mbuf.size + 2)) {
                ok = 0;
                break;
            }
        }
        else if (action == NOISE_ACTION_READ_MESSAGE) {
            message_size = echo_recv(s->session_soc, message, sizeof(message));
            if (!message_size) {
                ok = 0;
                break;
            }
            noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read handshake", err);
                ok = 0;
                break;
            }
        }
        else {
            break;
        }
    }
    if (ok && noise_handshakestate_get_action(handshake) != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "protocol handshake failed\n");
        ok = 0;
    }
    if (ok) {
        err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
        if (err != NOISE_ERROR_NONE) {
            noise_perror("split to start data transfer", err);
            ok = 0;
        }
    }
    noise_handshakestate_free(handshake);
    handshake = 0;


    SERVER_PACKET packet;
    int parse_state = PARSE_None;

    fd_set readfds;
    char pool[0x800];
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(s->session_soc, &readfds);
        int maxfd = s->session_soc;
        if (s->service_soc != -1) {
            FD_SET(s->service_soc, &readfds);
            maxfd = (s->session_soc > s->service_soc) ? s->session_soc : s->service_soc;
        }
        int activity = select(maxfd + 1, &readfds, 0, 0, 0);
        if (activity <= 0) {
            if (errno == EINTR) {
                continue;
            }
        }
        if (s->service_soc != -1) {
            if (FD_ISSET(s->service_soc, &readfds)) {
                int len = recv(s->service_soc, pool, sizeof(pool), 0);
                printf("len from service: %d\n", len);
                if (len <= 0) {
                    break;
                }
                int buf_len = 0;
                char* buffer = build_data_pkt(pool, len, &buf_len);
                memcpy(message + 2, buffer, buf_len);
                free(buffer);
                SEND_VIA_NOISE;
            }
        }
        if (FD_ISSET(s->session_soc, &readfds)) {
            message_size = echo_recv(s->session_soc, message, sizeof(message));
            if (!message_size) {
                break;
            }
            noise_buffer_set_inout(mbuf, message + 2, message_size - 2, sizeof(message) - 2);
            err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("read", err);
                break;
            }
            int len = mbuf.size;
            for (int i = 0; i < len; i++) {
                UINT8 c = mbuf.data[i];
                if (parse_state == PARSE_None) {
                    packet.cmd = c;

                    packet.len = 0;
                    packet.recv = 0;
                    parse_state++;
                }
                else if (parse_state >= PARSE_Cmd && parse_state < PARSE_Len_3) {
                    UINT32 tmp = c;
                    tmp <<= (8 * (parse_state - 1));
                    packet.len += tmp;

                    parse_state++;
                    if (parse_state == PARSE_Len_3) {
                        if (packet.cmd == PKT_PING) {
                            s->ping = 0;
                            parse_state == PARSE_None;
                            continue;
                        }
                        packet.payload = (char*)malloc(packet.len);
                    }
                }
                else if (parse_state == PARSE_Len_3) {
                    cp = min((len - i), (packet.len - packet.recv));
                    memcpy(packet.payload + packet.recv, mbuf.data + i, cp);
                    packet.recv += cp;

                    // process data packet
                    if (packet.recv >= packet.len) {
                        if (packet.cmd == PKT_DATA) {
                            if (s->service_soc != -1) {
                                if (my_send(s->service_soc, packet.payload, packet.len) != 0) {
                                    free(packet.payload);
                                    goto END_TH;
                                }
                                printf("send success\n");
                            }
                        }
                        else if (packet.cmd == PKT_HANDSHAKE) {
                            char hostname[0x400] = { 0 };
                            strcpy(hostname, packet.payload);
                            UINT8* pos = packet.payload + strlen(hostname) + 1;
                            UINT16 port = pos[1];
                            port <<= 8; port += pos[0];
                            printf("host: %s:%d\n", hostname, port);

                            s->service_soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                            struct sockaddr_in serviceAddr;
                            serviceAddr.sin_family = AF_INET;
                            serviceAddr.sin_port = htons(port);
                            serviceAddr.sin_addr.s_addr = inet_addr(hostname);

                            if (connect(s->service_soc, (struct sockaddr*)&serviceAddr, sizeof(serviceAddr)) == -1) {
                                free(packet.payload);
                                goto END_TH;
                            }
                            printf("connect success\n");
                        }
                        free(packet.payload);
                        parse_state = PARSE_None;
                    }

                    i += cp - 1;
                }
            }
        }
    }

END_TH:
    noise_cipherstate_free(send_cipher);
    noise_cipherstate_free(recv_cipher);

    close(s->session_soc);
    if (s->service_soc != -1) {
        close(s->service_soc);
    }

    return 0;
}
