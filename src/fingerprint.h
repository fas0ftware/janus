#ifndef JANUS_FINGERPRINT_H
#define JANUS_FINGERPRINT_H

/*
 * Service and version detection (--sv): turn the bytes a service sent back
 * into "what really runs here", e.g. ssh / OpenSSH / 9.6p1.
 *
 * Everything in this file is pure parsing: no sockets, no global state, so
 * every matcher can be unit-tested with canned replies. The bytes come from
 * an untrusted peer, so every parser checks lengths before it reads and every
 * string it produces is printable ASCII only (no terminal escapes).
 */

#include <stdbool.h> /* bool */
#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */

#define DETECTED_SERVICE_SIZE 16
#define DETECTED_PRODUCT_SIZE 32
#define DETECTED_VERSION_SIZE 32
#define DETECTED_INFO_SIZE 64

#define CERT_TEXT_SIZE 64
#define CERT_TIME_SIZE 24 /* "2026-11-14T07:25:12Z" */
#define CERT_KEY_SIZE 24
#define CERT_MAX_NAMES 8

/*
 * The server certificate of a TLS port: only the parts that matter when you
 * check your own network (who is it for, who signed it, until when).
 */
typedef struct {
    bool present;
    bool self_signed;                      /* issuer and subject are the same name */
    char subject[CERT_TEXT_SIZE];          /* common name (CN), or the organization (O) if there is none */
    char issuer[CERT_TEXT_SIZE];           /* same, for the signer */
    char not_before[CERT_TIME_SIZE];       /* ISO 8601 UTC, comparable with strcmp */
    char not_after[CERT_TIME_SIZE];
    char key[CERT_KEY_SIZE];               /* "RSA 2048", "EC P-256", "Ed25519" */
    char names[CERT_MAX_NAMES][CERT_TEXT_SIZE]; /* subjectAltName: DNS names and IP addresses */
    size_t name_count;
} tls_certificate;

/* What a probe found out about one open port. Empty strings mean "unknown". */
typedef struct {
    char service[DETECTED_SERVICE_SIZE]; /* protocol actually spoken: "ssh", "http", "tls", ... */
    char product[DETECTED_PRODUCT_SIZE]; /* software: "OpenSSH", "nginx", "MariaDB", ... */
    char version[DETECTED_VERSION_SIZE]; /* "9.6p1", "1.24.0", ... */
    char info[DETECTED_INFO_SIZE];       /* extra detail: "Ubuntu", "TLS 1.3, TLS_AES_256_GCM_SHA384", ... */
    tls_certificate certificate;         /* TLS only; .present is false otherwise */
} service_info;

/* What Janus sent before the reply arrived. The same bytes can mean different things. */
typedef enum {
    PROBE_GREETING, /* nothing: the service spoke first (SSH, FTP, SMTP, MySQL, VNC, ...) */
    PROBE_HTTP,     /* "HEAD / HTTP/1.0" */
    PROBE_TLS,      /* a TLS ClientHello (see tls_client_hello) */
    PROBE_PGSQL,    /* a PostgreSQL SSLRequest: the server answers one byte, 'S' or 'N' */
} probe_kind;

/*
 * Identify a TCP service from its reply to `probe`. Returns true and fills
 * *out when the reply matches a known protocol; returns false (and leaves
 * *out empty) otherwise. Never reads beyond data[length - 1].
 */
bool identify_tcp_reply(probe_kind probe, const unsigned char *data, size_t length, service_info *out);

/*
 * Identify the reply to one of Janus' UDP probes (DNS 53, NTP 123, NetBIOS 137,
 * SSDP 1900, mDNS 5353; see udp_scan.h). Returns false for other ports or
 * replies that do not parse.
 */
bool identify_udp_reply(uint16_t port, const unsigned char *data, size_t length, service_info *out);

/*
 * Write a TLS ClientHello into buffer and return its length (0 if buffer is
 * too small). It offers TLS 1.3 and 1.2 with common cipher suites and an
 * X25519 key share, so modern servers answer with a real ServerHello.
 *
 * server_name (may be NULL or "") is sent as SNI; servers that host several
 * names need it to pick the right certificate. With tls12_only, TLS 1.3 is
 * not offered: a TLS 1.2 server sends its certificate unencrypted, which is
 * the only way to read it without finishing the handshake.
 */
size_t tls_client_hello(unsigned char *buffer, size_t buffer_size, const char *server_name, bool tls12_only);

/*
 * For a reply that starts with a TLS record: true once everything Janus
 * wants is in (the ServerHello, and for TLS 1.2 and older the first
 * certificate), or once nothing more can be expected (an alert, a different
 * record type). False means: keep reading.
 */
bool tls_reply_complete(const unsigned char *data, size_t length);

/* Parse one DER-encoded X.509 certificate. Returns false if it is malformed or truncated. */
bool parse_certificate(const unsigned char *der, size_t length, tls_certificate *out);

/* Validity at time now ("YYYY-MM-DDTHH:MM:SSZ", e.g. the scan's start time). */
bool certificate_expired(const tls_certificate *certificate, const char *now);
bool certificate_not_yet_valid(const tls_certificate *certificate, const char *now);

/* The 8-byte PostgreSQL SSLRequest message. Returns its length (0 if buffer is too small). */
size_t pgsql_ssl_request(unsigned char *buffer, size_t buffer_size);

/*
 * One line for the VERSION column: "OpenSSH 9.6p1 (Ubuntu-3ubuntu13)".
 * Writes "" when nothing but the service name is known.
 */
void format_detected_version(const service_info *info, char *out, size_t out_size);

#endif /* JANUS_FINGERPRINT_H */
