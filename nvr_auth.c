#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define NVR_PORT      80
#define USERNAME      "admin"
#define RTMP_VERSION  3
#define RTMP_CHUNK_SIZE 128

#define MAX_PACKET_SIZE (16 * 1024 * 1024)
#define MAX_CHUNK_SIZE  (1024 * 1024)

typedef struct {
    uint8_t  fmt;
    uint32_t csid;

    uint32_t timestamp;
    uint32_t timestamp_delta;

    uint32_t message_length;
    uint8_t  message_type;
    uint32_t message_stream_id;

    uint8_t  has_extended_timestamp;

    uint8_t *body;
    uint32_t body_received;

    int active;
} RTMPChunkStream;

// Utility
static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static uint32_t read_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2]);
}

static uint32_t read_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

// TCP
static int tcp_connect(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        die("socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "NVR_HOST must be an IPv4 address\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[+] Connecting to NVR port %d\n", port);

    struct timeval timeout = {.tv_sec = 10};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static int recv_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);

        if (n == 0)
            return 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        got += n;
    }

    return 1;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (n == 0)
            return -1;

        sent += n;
    }

    return 0;
}

// RTMP handshake                                           
static int rtmp_handshake(int fd) {
    uint8_t c0c1[1537];

    memset(c0c1, 0, sizeof(c0c1));

    c0c1[0] = RTMP_VERSION;

    /*
     * C1:
     * timestamp = 0
     * zero/version bytes are sufficient for this NVR.
     */

    if (send_all(fd, c0c1, sizeof(c0c1)) < 0)
        return -1;

    uint8_t s0s1s2[3073];

    if (recv_exact(fd, s0s1s2, sizeof(s0s1s2)) <= 0)
        return -1;

    /*
     * Send C2 = server C1.
     */
    if (send_all(fd, s0s1s2 + 1, 1536) < 0)
        return -1;

    fprintf(stderr, "[+] RTMP handshake complete\n");

    return 0;
}

// AMF0
static size_t amf_string(uint8_t *out, size_t pos, const char *s) {
    size_t len = strlen(s);

    out[pos++] = 0x02;

    out[pos++] = (len >> 8) & 0xff;
    out[pos++] = len & 0xff;

    memcpy(out + pos, s, len);
    pos += len;

    return pos;
}

static size_t amf_key(uint8_t *out, size_t pos, const char *s) {
    size_t len = strlen(s);
    out[pos++] = (len >> 8) & 0xff;
    out[pos++] = len & 0xff;
    memcpy(out + pos, s, len);
    return pos + len;
}

static size_t amf_number(uint8_t *out, size_t pos, double value) {
    union {
        double d;
        uint64_t u;
    } v;

    v.d = value;

    out[pos++] = 0x00;

    /*
     * AMF numbers are big endian.
     */
    for (int i = 7; i >= 0; i--)
        out[pos++] = (v.u >> (i * 8)) & 0xff;

    return pos;
}

static double read_amf_number(const uint8_t *p) {
    union { uint64_t u; double d; } value = {0};
    for (int i = 0; i < 8; i++)
        value.u = (value.u << 8) | p[i];
    return value.d;
}

static size_t amf_null(uint8_t *out, size_t pos) {
    out[pos++] = 0x05;
    return pos;
}

// RTMP basic packet sender  
static int rtmp_send_message(
    int fd,
    uint8_t csid,
    uint8_t message_type,
    uint32_t stream_id,
    const uint8_t *body,
    uint32_t body_len) {
    /*
     * For our outgoing messages we use:
     *
     * fmt 0
     * basic header
     * timestamp = 0
     * message length
     * message type
     * little-endian message stream ID
     */

    uint8_t header[12];

    size_t header_len = 0;

    if (csid < 64) {
        header[header_len++] = csid;
    } else {
        fprintf(stderr, "Unsupported CSID\n");
        return -1;
    }

    header[header_len++] = 0x00;
    header[header_len++] = 0x00;
    header[header_len++] = 0x00;

    header[header_len++] = (body_len >> 16) & 0xff;
    header[header_len++] = (body_len >> 8) & 0xff;
    header[header_len++] = body_len & 0xff;

    header[header_len++] = message_type;

    write_le32(header + header_len, stream_id);
    header_len += 4;

    if (send_all(fd, header, header_len) < 0)
        return -1;

    /*
     * RTMP default chunk size is 128.
     */
    uint32_t offset = 0;

    while (offset < body_len) {
        uint32_t chunk = body_len - offset;

        if (chunk > RTMP_CHUNK_SIZE)
            chunk = RTMP_CHUNK_SIZE;

        if (send_all(fd, body + offset, chunk) < 0)
            return -1;

        offset += chunk;

        if (offset < body_len) {
            /*
             * fmt 3 continuation header.
             */
            uint8_t continuation = 0xc0 | csid;

            if (send_all(fd, &continuation, 1) < 0)
                return -1;
        }
    }

    return 0;
}

// Connect command  
static int send_connect(int fd, const char *host) {
    uint8_t body[1024];
    char tc_url[64];
    size_t p = 0;

    if (snprintf(tc_url, sizeof(tc_url), "rtmp://%s:%d/", host, NVR_PORT) >= (int)sizeof(tc_url))
        return -1;

    p = amf_string(body, p, "connect");
    p = amf_number(body, p, 1.0);

    /*
     * command object
     */
    body[p++] = 0x03;

    p = amf_key(body, p, "app");
    p = amf_string(body, p, "");

    p = amf_key(body, p, "type");
    p = amf_string(body, p, "nonprivate");

    p = amf_key(body, p, "flashVer");
    p = amf_string(body, p, "100");

    p = amf_key(body, p, "tcUrl");
    p = amf_string(body, p, tc_url);

    p = amf_key(body, p, "fpad");
    body[p++] = 0x01;
    body[p++] = 0x00;

    p = amf_key(body, p, "capabilities");
    p = amf_number(body, p, 15.0);

    p = amf_key(body, p, "audioCodecs");
    p = amf_number(body, p, 4071.0);

    p = amf_key(body, p, "videoCodecs");
    p = amf_number(body, p, 252.0);

    p = amf_key(body, p, "videoFunction");
    p = amf_number(body, p, 1.0);

    /*
     * Object end.
     */
    body[p++] = 0x00;
    body[p++] = 0x00;
    body[p++] = 0x09;

    fprintf(stderr, "[+] Sending connect\n");

    return rtmp_send_message(fd, 3, 20, 0, body, p);
}

// MD5
static void md5_hex(const char *input, char output[33]) {
    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5(
        (const unsigned char *)input,
        strlen(input),
        digest
    );

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", digest[i]);

    output[32] = '\0';
}

// RTMP raw reader
static RTMPChunkStream chunk_streams[64];
static uint32_t incoming_chunk_size = RTMP_CHUNK_SIZE;

static RTMPChunkStream *get_chunk_stream(uint32_t csid) {
    if (csid >= 64)
        return NULL;

    return &chunk_streams[csid];
}

static int recv_byte(int fd, uint8_t *b) {
    return recv_exact(fd, b, 1);
}

/*
 * Read a complete RTMP message.
 *
 * This deliberately handles only the chunk stream forms actually
 * encountered in this NVR's traffic, but supports fmt 0-3 and
 * extended CSIDs/timestamps.
 */
static int rtmp_read_message(
    int fd,
    uint8_t **out_body,
    uint32_t *out_len,
    uint8_t *out_type,
    uint32_t *out_stream_id,
    uint32_t *out_timestamp,
    uint32_t *out_csid) {
    while (1) {
        uint8_t first;

        if (recv_byte(fd, &first) <= 0) {
            return -1;
        }

        uint8_t fmt = first >> 6;
        uint32_t csid = first & 0x3f;

        if (csid == 0) {
            uint8_t b;

            if (recv_byte(fd, &b) <= 0)
                return -1;

            csid = 64 + b;
        } else if (csid == 1) {
            uint8_t b0, b1;

            if (recv_byte(fd, &b0) <= 0)
                return -1;

            if (recv_byte(fd, &b1) <= 0)
                return -1;

            csid = 64 + b0 + ((uint32_t)b1 << 8);
        }

        /*
         * This implementation supports CSIDs up to 63.
         * The NVR's media stream in our capture uses low CSIDs.
         */
        if (csid >= 64) {
            fprintf(stderr, "[-] Unsupported CSID %u\n", csid);
            return -1;
        }

        RTMPChunkStream *cs = get_chunk_stream(csid);

        if (!cs)
            return -1;

        cs->fmt = fmt;

        if (fmt != 3 && cs->active && cs->body_received < cs->message_length) {
            fprintf(stderr, "[-] New header before message complete on CSID %u\n", csid);
            return -1;
        }

        if (fmt == 0) {
            uint8_t h[11];

            if (recv_exact(fd, h, 11) <= 0)
                return -1;

            uint32_t timestamp = read_be24(h);
            uint32_t message_length = read_be24(h + 3);
            uint8_t message_type = h[6];
            uint32_t stream_id = read_le32(h + 7);

            cs->timestamp = timestamp;
            cs->timestamp_delta = 0;
            cs->message_length = message_length;
            cs->message_type = message_type;
            cs->message_stream_id = stream_id;
            cs->has_extended_timestamp = timestamp == 0xffffff;

            if (cs->has_extended_timestamp) {
                uint8_t ext[4];

                if (recv_exact(fd, ext, 4) <= 0)
                    return -1;

                cs->timestamp = ((uint32_t)ext[0] << 24) | ((uint32_t)ext[1] << 16) |
                                ((uint32_t)ext[2] << 8) | ext[3];
            }

            free(cs->body);
            cs->body = NULL;

            if (message_length > MAX_PACKET_SIZE) {
                fprintf(stderr,
                        "[-] Refusing message of %u bytes\n",
                        message_length);
                return -1;
            }

            cs->body = malloc(message_length);

            if (!cs->body && message_length)
                return -1;

            cs->body_received = 0;
            cs->active = 1;
        }

        else if (fmt == 1) {
            uint8_t h[7];

            if (recv_exact(fd, h, 7) <= 0)
                return -1;

            uint32_t delta = read_be24(h);
            uint32_t message_length = read_be24(h + 3);
            uint8_t message_type = h[6];

            cs->timestamp_delta = delta;

            cs->message_length = message_length;
            cs->message_type = message_type;

            if (delta == 0xffffff) {
                uint8_t ext[4];

                if (recv_exact(fd, ext, 4) <= 0)
                    return -1;

                cs->timestamp_delta = ((uint32_t)ext[0] << 24) | ((uint32_t)ext[1] << 16) |
                                      ((uint32_t)ext[2] << 8) | ext[3];
            }
            cs->has_extended_timestamp = delta == 0xffffff;
            cs->timestamp += cs->timestamp_delta;

            free(cs->body);
            cs->body = NULL;

            if (message_length > MAX_PACKET_SIZE)
                return -1;

            cs->body = malloc(message_length);

            if (!cs->body && message_length)
                return -1;

            cs->body_received = 0;
            cs->active = 1;
        }

        else if (fmt == 2) {
            uint8_t h[3];

            if (recv_exact(fd, h, 3) <= 0)
                return -1;

            uint32_t delta = read_be24(h);

            cs->timestamp_delta = delta;

            if (delta == 0xffffff) {
                uint8_t ext[4];

                if (recv_exact(fd, ext, 4) <= 0)
                    return -1;

                cs->timestamp_delta = ((uint32_t)ext[0] << 24) | ((uint32_t)ext[1] << 16) |
                                      ((uint32_t)ext[2] << 8) | ext[3];
            }
            cs->has_extended_timestamp = delta == 0xffffff;
            cs->timestamp += cs->timestamp_delta;

            /*
             * Message length/type/stream ID remain unchanged.
             */
            cs->body_received = 0;

            if (cs->body) {
                free(cs->body);
                cs->body = NULL;
            }

            cs->body = malloc(cs->message_length);

            if (!cs->body && cs->message_length)
                return -1;

            cs->active = 1;
        }

        else if (fmt == 3) {
            /*
             * No message header.
             *
             * If this is a continuation chunk, all metadata comes
             * from the previous chunk.
             */
            if (!cs->message_length)
                return -1;
            if (cs->has_extended_timestamp) {
                uint8_t ext[4];
                if (recv_exact(fd, ext, 4) <= 0)
                    return -1;
            }
            if (!cs->active) {
                cs->timestamp += cs->timestamp_delta;
                cs->body = malloc(cs->message_length);
                if (!cs->body)
                    return -1;
                cs->body_received = 0;
                cs->active = 1;
            }
        }

        else {
            return -1;
        }

        /*
         * Read this chunk's body.
         */
        uint32_t remaining =
            cs->message_length - cs->body_received;

        uint32_t chunk_size = incoming_chunk_size;

        if (remaining < chunk_size)
            chunk_size = remaining;

        if (chunk_size > 0) {
            if (recv_exact(
                    fd,
                    cs->body + cs->body_received,
                    chunk_size) <= 0)
                return -1;

            cs->body_received += chunk_size;
        }

        /*
         * Message complete.
         */
        if (cs->body_received == cs->message_length) {
            uint8_t *body = cs->body;

            *out_body = body;
            *out_len = cs->message_length;
            *out_type = cs->message_type;
            *out_stream_id = cs->message_stream_id;
            *out_timestamp = cs->timestamp;
            *out_csid = csid;

            cs->body = NULL;
            cs->body_received = 0;
            cs->active = 0;

            return 0;
        }
    }
}

// Find challenge 
static int find_challenge(
    const uint8_t *body,
    uint32_t len,
    char *challenge,
    size_t challenge_size) {
    const char needle[] = "challenge=";

    for (uint32_t i = 0; i + strlen(needle) < len; i++) {
        if (memcmp(body + i, needle, strlen(needle)) == 0) {
            const uint8_t *p =
                body + i + strlen(needle);

            size_t n = 0;

            while ((p + n) < body + len &&
                   n + 1 < challenge_size) {

                char c = p[n];

                if (c == '&' ||
                    c == '\0' ||
                    c == '"' ||
                    c == '\'')
                    break;

                challenge[n++] = c;
            }

            challenge[n] = '\0';

            return n > 0 ? 0 : -1;
        }
    }

    return -1;
}

// Login
static int send_login(
    int fd,
    const char *challenge,
    const char *password) {
    char digest[33];
    char method[512];

    char input[512];

    if (snprintf(
        input,
        sizeof(input),
        "%s:%s",
        challenge,
        password
    ) >= (int)sizeof(input)) {
        fprintf(stderr, "[-] Credential input too long\n");
        return -1;
    }

    md5_hex(input, digest);

    if (snprintf(
        method,
        sizeof(method),
        "login?method=md5&nonce=%s&username=%s&digest=%s",
        challenge,
        USERNAME,
        digest
    ) >= (int)sizeof(method)) {
        fprintf(stderr, "[-] Authentication challenge too long\n");
        return -1;
    }

    uint8_t body[1024];
    size_t p = 0;

    p = amf_string(body, p, method);
    p = amf_number(body, p, 1.0);
    p = amf_null(body, p);

    fprintf(stderr, "[+] Sending login...\n");

    return rtmp_send_message(
        fd,
        3,
        20,
        0,
        body,
        p
    );
}

// createStream  
static int send_create_stream(int fd) {
    uint8_t body[256];

    size_t p = 0;

    p = amf_string(body, p, "createStream");
    p = amf_number(body, p, 2.0);
    p = amf_null(body, p);

    return rtmp_send_message(
        fd,
        3,
        20,
        0,
        body,
        p
    );
}

// FCSubscribe
static int send_fcsubscribe(int fd, const char *stream) {
    uint8_t body[256];

    size_t p = 0;

    p = amf_string(body, p, "FCSubscribe");
    p = amf_number(body, p, 0.0);
    p = amf_null(body, p);
    p = amf_string(body, p, stream);

    return rtmp_send_message(
        fd,
        4,
        20,
        0,
        body,
        p
    );
}

// play
static int send_play(
    int fd,
    uint32_t stream_id,
    const char *stream) {
    uint8_t body[256];

    size_t p = 0;

    p = amf_string(body, p, "play");
    p = amf_number(body, p, 0.0);
    p = amf_null(body, p);
    p = amf_string(body, p, stream);

    return rtmp_send_message(
        fd,
        8,
        20,
        stream_id,
        body,
        p
    );
}

// Extract AVC information  
static void inspect_video(
    const uint8_t *body,
    uint32_t len,
    uint32_t timestamp,
    FILE *out) {
    (void)timestamp;
    if (len < 5 || (body[0] & 0x0f) != 7 || body[1] != 1)
        return;
    uint32_t pos = 5;
    while (pos + 4 <= len) {
        uint32_t nal_len = ((uint32_t)body[pos] << 24) |
                           ((uint32_t)body[pos + 1] << 16) |
                           ((uint32_t)body[pos + 2] << 8) | body[pos + 3];
        pos += 4;
        if (!nal_len || nal_len > len - pos) {
            fprintf(stderr, "[-] Invalid video NAL length\n");
            return;
        }
        static const uint8_t start_code[] = {0, 0, 0, 1};
        if (fwrite(start_code, 1, 4, out) != 4 ||
            fwrite(body + pos, 1, nal_len, out) != nal_len)
            die("write video");
        pos += nal_len;
    }
    if (pos != len)
        fprintf(stderr, "[-] Trailing video payload bytes\n");
    fflush(out);
}

// Main
int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[1]) != 1 || argv[1][0] < '0' || argv[1][0] > '7' ||
        strlen(argv[2]) != 1 || (argv[2][0] != '0' && argv[2][0] != '1')) {
        fprintf(stderr, "Usage: %s <channel 0-7> <stream 0|1> (video on stdout)\n", argv[0]);
        return EXIT_FAILURE;
    }
    char stream_name[16];
    snprintf(stream_name, sizeof(stream_name), "ch%c_%c.264", argv[1][0], argv[2][0]);
    const char *password = getenv("NVR_PASSWORD");
    if (!password || !*password) {
        fprintf(stderr, "Set NVR_PASSWORD in the environment\n");
        return EXIT_FAILURE;
    }
    const char *host = getenv("NVR_HOST");
    struct in_addr host_addr;
    if (!host || inet_pton(AF_INET, host, &host_addr) != 1) {
        fprintf(stderr, "Set NVR_HOST to the NVR's IPv4 address\n");
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    FILE *video_file = stdout;
    setvbuf(video_file, NULL, _IONBF, 0);

    for (;;) {
    memset(chunk_streams, 0, sizeof(chunk_streams));
    incoming_chunk_size = RTMP_CHUNK_SIZE;

    fprintf(stderr, "NVR raw RTMP client\n");
    fprintf(stderr, "===================\n");

    int fd = tcp_connect(host, NVR_PORT);
    if (fd < 0) {
        sleep(1);
        continue;
    }

    if (rtmp_handshake(fd) < 0) {
        fprintf(stderr, "[-] RTMP handshake failed\n");
        goto reconnect;
    }

    if (send_connect(fd, host) < 0) {
        fprintf(stderr, "[-] Failed to send connect\n");
        goto reconnect;
    }

    char challenge[256];
    memset(challenge, 0, sizeof(challenge));

    int login_sent = 0;
    int authenticated = 0;
    int create_sent = 0;
    int seen_video = 0;
    uint32_t stream_id = 0;

    fprintf(stderr, "[+] Playing %s to stdout\n", stream_name);

    while (1) {
        uint8_t *body = NULL;
        uint32_t len = 0;
        uint8_t type = 0;
        uint32_t message_stream_id = 0;
        uint32_t timestamp = 0;
        uint32_t csid = 0;

        if (rtmp_read_message(
                fd,
                &body,
                &len,
                &type,
                &message_stream_id,
                &timestamp,
                &csid) < 0) {

            fprintf(stderr,
                    "[-] RTMP read failed\n");

            break;
        }

        (void)csid;
        (void)message_stream_id;

        /*
         * AMF command message.
         */
        if (type == 1) {
            if (len != 4) {
                fprintf(stderr, "[-] Invalid RTMP chunk size\n");
                free(body);
                break;
            }
            incoming_chunk_size = ((uint32_t)body[0] << 24) | ((uint32_t)body[1] << 16) |
                                  ((uint32_t)body[2] << 8) | body[3];
            if (!incoming_chunk_size || incoming_chunk_size > MAX_CHUNK_SIZE) {
                fprintf(stderr, "[-] Invalid RTMP chunk size\n");
                free(body);
                break;
            }
            fprintf(stderr, "[+] Incoming chunk size: %u\n", incoming_chunk_size);
        }
        else if (type == 20) {
            if (len > 0) {
                /*
                 * Need authentication.
                 */
                if (!login_sent && find_challenge(
                        body,
                        len,
                        challenge,
                        sizeof(challenge)) == 0) {

                    fprintf(stderr, "[+] Authentication challenge received\n");

                    if (send_login(
                            fd,
                            challenge,
                            password) < 0) {

                        fprintf(stderr,
                                "[-] Login send failed\n");

                        free(body);
                        break;
                    }

                    login_sent = 1;
                }

                /*
                 * Login response.
                 *
                 * The NVR returns:
                 *
                 * _result
                 * transaction 1
                 * 200
                 */
                if (login_sent && !authenticated && len >= 29 &&
                    memcmp(body, "\x02\x00\x07_result\x00", 11) == 0 &&
                    read_amf_number(body + 11) == 1.0 && body[19] == 5 &&
                    body[20] == 0 && read_amf_number(body + 21) == 200.0) {
                    authenticated = 1;
                    fprintf(stderr, "[+] Authenticated\n");
                    if (send_create_stream(fd) < 0) {
                        free(body);
                        break;
                    }
                    create_sent = 1;
                }

                /*
                 * createStream response.
                 *
                 * Transaction 2 returns the allocated stream ID.
                 */
                if (create_sent && stream_id == 0 && len >= 29 &&
                    memcmp(body, "\x02\x00\x07_result\x00", 11) == 0 &&
                    read_amf_number(body + 11) == 2.0 && body[19] == 5 &&
                    body[20] == 0) {
                    double id = read_amf_number(body + 21);
                    if (id >= 1 && id <= UINT32_MAX && id == (uint32_t)id) {
                        stream_id = (uint32_t)id;

                        fprintf(stderr, 
                            "[+] Using media stream ID: %u\n",
                            stream_id
                        );

                        if (send_fcsubscribe(
                                fd,
                                stream_name) < 0) {

                            fprintf(stderr,
                                    "[-] FCSubscribe failed\n");

                            free(body);
                            break;
                        }

                        if (send_play(
                                fd,
                                stream_id,
                                stream_name) < 0) {

                            fprintf(stderr,
                                    "[-] play failed\n");

                            free(body);
                            break;
                        }

                        fprintf(stderr, 
                            "[+] Playing %s\n",
                            stream_name
                        );
                    }
                }
            }
        }

        /*
         * Video.
         *
         * Standard RTMP video message type is 9.
         */
        else if (type == 9) {
            if (!seen_video) {
                fprintf(stderr, "[+] Video received\n");
                seen_video = 1;
            }
            inspect_video(
                body,
                len,
                timestamp,
                video_file
            );
        }

        free(body);
    }

reconnect:
    close(fd);

    for (int i = 0; i < 64; i++)
        free(chunk_streams[i].body);

    fprintf(stderr, "[-] Connection ended; reconnecting\n");
    sleep(1);
    }
}
