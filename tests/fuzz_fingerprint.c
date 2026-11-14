/*
 * Mutation fuzzer for the --sv parsers: every reply a scanned service sends
 * is attacker-controlled. Build with AddressSanitizer + UBSan (make fuzz):
 * any out-of-bounds read, overflow or undefined behaviour aborts the run.
 *
 * Seeds are realistic replies (SSH, HTTP, TLS ServerHello + certificate,
 * MySQL, DNS, NTP, NetBIOS, mDNS, ...). Each iteration takes a seed and
 * applies a few mutations: bit flips, byte overwrites with boundary values,
 * truncation, insertion, duplication and "length field" bumps (0x00/0x7f/
 * 0x80/0xff at random positions). Every output string must stay printable
 * ASCII and NUL-terminated.
 *
 * usage: fuzz_fingerprint [iterations] [seed]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/fingerprint.h"

#define MAX_INPUT 4096

static uint64_t state = 0x9e3779b97f4a7c15ULL;

static uint64_t next_random(void)
{
    /* xorshift64*: fast and reproducible from the seed */
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
}

static size_t below(size_t n)
{
    return n == 0 ? 0 : (size_t)(next_random() % n);
}

typedef struct {
    const unsigned char *data;
    size_t length;
} seed;

#define TEXT_SEED(s) {(const unsigned char *)(s), sizeof(s) - 1}

static const unsigned char tls_hello[] = {
    0x16, 0x03, 0x03, 0x00, 0x3e, 0x02, 0x00, 0x00, 0x3a, 0x03, 0x03, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x13, 0x01, 0x00, 0x00, 0x12, 0x00, 0x2b, 0x00, 0x02, 0x03,
    0x04, 0x00, 0x33, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
};
static const unsigned char tls_alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
static const unsigned char mysql[] = "\x4a\x00\x00\x00\x0a" "8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00";
static const unsigned char mysql_error[] = "\x45\x00\x00\x00\xff\x6a\x04Host '10.0.0.5' is not allowed to connect";
static const unsigned char dns[] = {0x12, 0x34, 0x81, 0x85, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0, 1,
                                    0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0, 10, 0, 2, 0xc0, 0x0c};
static const unsigned char mdns[] = {
    0x12, 0x34, 0x84, 0x00, 0, 0, 0, 2, 0, 0, 0, 0,
    9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 7, '_', 'd', 'n', 's', '-', 's', 'd', 4, '_', 'u', 'd', 'p',
    5, 'l', 'o', 'c', 'a', 'l', 0, 0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 12,
    4, '_', 'i', 'p', 'p', 4, '_', 't', 'c', 'p', 0xc0, 35,
    0xc0, 12, 0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 2, 0xc0, 42,
};

/* The X.509 test certificate from test_fingerprint.c, wrapped in a TLS 1.2 flight at run time. */
#include "fuzz_certificate.inc"

static unsigned char tls_flight[2048];
static size_t tls_flight_length;
static unsigned char ntp[48] = {0x24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'G', 'P', 'S', 0};
static unsigned char netbios[12 + 34 + 10 + 1 + 2 * 18];

static void build_dynamic_seeds(void)
{
    /* ServerHello (TLS 1.2, no extensions) + Certificate message in one record */
    unsigned char *f = tls_flight;
    size_t hello_body = 2 + 32 + 1 + 2 + 1;
    size_t cert_list = 3 + sizeof certificate_der;
    size_t record = 4 + hello_body + 4 + 3 + cert_list;
    size_t n = 0;
    f[n++] = 0x16; f[n++] = 0x03; f[n++] = 0x03;
    f[n++] = (unsigned char)(record >> 8); f[n++] = (unsigned char)record;
    f[n++] = 0x02; f[n++] = 0; f[n++] = 0; f[n++] = (unsigned char)hello_body;
    f[n++] = 0x03; f[n++] = 0x03;
    memset(f + n, 0x22, 32); n += 32;
    f[n++] = 0; f[n++] = 0xc0; f[n++] = 0x2b; f[n++] = 0;
    f[n++] = 11; f[n++] = 0; f[n++] = (unsigned char)((cert_list + 3) >> 8); f[n++] = (unsigned char)(cert_list + 3);
    f[n++] = 0; f[n++] = (unsigned char)(cert_list >> 8); f[n++] = (unsigned char)cert_list;
    f[n++] = 0; f[n++] = (unsigned char)(sizeof certificate_der >> 8); f[n++] = (unsigned char)sizeof certificate_der;
    memcpy(f + n, certificate_der, sizeof certificate_der); n += sizeof certificate_der;
    tls_flight_length = n;

    unsigned char *b = netbios;
    static const unsigned char head[] = {0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0x20};
    memcpy(b, head, sizeof head);
    memset(b + 13, 'A', 32);
    b[56] = 2;
    memcpy(b + 57, "OFFICE-PC      ", 15); b[57 + 16] = 0x04;
    memcpy(b + 75, "WORKGROUP      ", 15); b[75 + 16] = 0x84;
}

static void check_text(const char *text, size_t size, const char *what)
{
    size_t length = strnlen(text, size);
    if (length == size) {
        fprintf(stderr, "FAIL: %s is not NUL-terminated\n", what);
        abort();
    }
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c >= 0x7f) {
            fprintf(stderr, "FAIL: %s contains byte 0x%02x\n", what, c);
            abort();
        }
    }
}

static void check_info(const service_info *info)
{
    check_text(info->service, sizeof info->service, "service");
    check_text(info->product, sizeof info->product, "product");
    check_text(info->version, sizeof info->version, "version");
    check_text(info->info, sizeof info->info, "info");
    check_text(info->starttls, sizeof info->starttls, "starttls");
    const tls_certificate *c = &info->certificate;
    check_text(c->subject, sizeof c->subject, "cert subject");
    check_text(c->issuer, sizeof c->issuer, "cert issuer");
    check_text(c->not_before, sizeof c->not_before, "cert not_before");
    check_text(c->not_after, sizeof c->not_after, "cert not_after");
    check_text(c->key, sizeof c->key, "cert key");
    if (c->name_count > CERT_MAX_NAMES) {
        fprintf(stderr, "FAIL: name_count %zu\n", c->name_count);
        abort();
    }
    for (size_t i = 0; i < c->name_count; i++) {
        check_text(c->names[i], sizeof c->names[i], "cert name");
    }
    char line[256];
    format_detected_version(info, line, sizeof line);
    check_text(line, sizeof line, "version line");
}

static size_t mutate(unsigned char *buffer, size_t length)
{
    static const unsigned char interesting[] = {0x00, 0x01, 0x02, 0x0a, 0x0d, 0x1b, 0x20, 0x7f, 0x80, 0x81,
                                                0x82, 0x83, 0x84, 0xc0, 0xfe, 0xff};
    size_t rounds = 1 + below(4);
    for (size_t r = 0; r < rounds; r++) {
        switch (below(7)) {
        case 0: /* flip a bit */
            if (length) buffer[below(length)] ^= (unsigned char)(1u << below(8));
            break;
        case 1: /* boundary value (length fields, DER tags, compression pointers) */
            if (length) buffer[below(length)] = interesting[below(sizeof interesting)];
            break;
        case 2: /* truncate */
            length = below(length + 1);
            break;
        case 3: /* insert random bytes */
            if (length < MAX_INPUT - 16) {
                size_t at = below(length + 1), count = 1 + below(8);
                memmove(buffer + at + count, buffer + at, length - at);
                for (size_t i = 0; i < count; i++) buffer[at + i] = (unsigned char)next_random();
                length += count;
            }
            break;
        case 4: /* duplicate a block (repeated records, lines, labels) */
            if (length && length < MAX_INPUT / 2) {
                size_t from = below(length), count = 1 + below(length - from);
                memcpy(buffer + length, buffer + from, count);
                length += count;
            }
            break;
        case 5: /* random byte */
            if (length) buffer[below(length)] = (unsigned char)next_random();
            break;
        default: /* 16-bit big-endian length bump */
            if (length >= 2) {
                size_t at = below(length - 1);
                buffer[at] = interesting[below(sizeof interesting)];
                buffer[at + 1] = interesting[below(sizeof interesting)];
            }
            break;
        }
    }
    return length;
}

int main(int argc, char **argv)
{
    unsigned long iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 200000;
    if (argc > 2) {
        state = strtoull(argv[2], NULL, 10) | 1;
    }
    build_dynamic_seeds();
    const seed seeds[] = {
        TEXT_SEED("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"),
        TEXT_SEED("SSH-1.99-Cisco-1.25\r\n"),
        TEXT_SEED("HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n"),
        TEXT_SEED("RTSP/1.0 200 OK\r\nServer: GStreamer RTSP server\r\n\r\n"),
        TEXT_SEED("220-Welcome\r\n220 (vsFTPd 3.0.5)\r\n"),
        TEXT_SEED("220 mx.example.org ESMTP Exim 4.96 Thu\r\n"),
        TEXT_SEED("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"),
        TEXT_SEED("+OK Dovecot ready.\r\n"),
        TEXT_SEED("RFB 003.008\n"),
        TEXT_SEED("-ERR unknown command 'HEAD'\r\n"),
        TEXT_SEED("ERROR\r\nERROR\r\n"),
        TEXT_SEED("AMQP\x00\x00\x09\x01"),
        TEXT_SEED("250-mail.test\r\n250-STARTTLS\r\n250 8BITMIME\r\n"),
        TEXT_SEED("HTTP/1.1 200 OK\r\nSERVER: Linux/5.4 UPnP/1.0 MiniUPnPd/2.2\r\n\r\n"),
        {tls_hello, sizeof tls_hello},
        {tls_alert, sizeof tls_alert},
        {mysql, sizeof mysql - 1},
        {mysql_error, sizeof mysql_error - 1},
        {dns, sizeof dns},
        {mdns, sizeof mdns},
        {ntp, sizeof ntp},
        {netbios, sizeof netbios},
        {tls_flight, 0}, /* length filled below */
        {certificate_der, sizeof certificate_der},
    };
    seed all[sizeof seeds / sizeof seeds[0]];
    memcpy(all, seeds, sizeof seeds);
    all[22].length = tls_flight_length;
    size_t seed_count = sizeof all / sizeof all[0];

    static const uint16_t udp_ports[] = {53, 123, 137, 1900, 5353, 9};
    static const probe_kind probes[] = {PROBE_GREETING, PROBE_HTTP, PROBE_TLS, PROBE_PGSQL};
    unsigned char *buffer = malloc(MAX_INPUT);
    unsigned long parsed = 0;
    for (unsigned long i = 0; i < iterations; i++) {
        const seed *s = &all[below(seed_count)];
        size_t length = s->length < MAX_INPUT ? s->length : MAX_INPUT;
        memcpy(buffer, s->data, length);
        length = mutate(buffer, length);

        /* An exact-size heap copy: ASan reports any read past the reply. */
        unsigned char *input = malloc(length ? length : 1);
        memcpy(input, buffer, length);
        service_info info;
        tls_certificate certificate;
        parsed += identify_tcp_reply(probes[below(4)], input, length, &info);
        check_info(&info);
        parsed += identify_udp_reply(udp_ports[below(6)], input, length, &info);
        check_info(&info);
        if (parse_certificate(input, length, &certificate)) {
            parsed++;
            service_info wrapper;
            memset(&wrapper, 0, sizeof wrapper);
            wrapper.certificate = certificate;
            check_info(&wrapper);
        }
        (void)tls_reply_complete(input, length);
        (void)line_reply_complete(input, length);
        (void)tagged_reply_complete(input, length, "J1");
        (void)smtp_offers_starttls(input, length);
        free(input);
    }
    free(buffer);
    printf("fuzz: %lu inputs, %lu parsed as something, no memory errors\n", iterations, parsed);
    return 0;
}
