#include "version_scan.h"

#include <stdio.h>      /* snprintf */
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memcmp */
#include <sys/socket.h> /* send, recv */
#include <unistd.h>     /* close */

#include "fingerprint.h"
#include "utils.h"

/* Bytes kept per reply: enough for HTTP headers or a TLS ServerHello. */
#define REPLY_MAX 2048
/* Largest probe Janus sends (the TLS ClientHello is about 200 bytes). */
#define PROBE_MAX 512
#define MAX_PROBES 3

int service_wait_ms(int timeout_ms)
{
    return timeout_ms < 1500 ? timeout_ms : 1500;
}

size_t http_head_request(const scan_target *target, char *buffer, size_t buffer_size)
{
    bool v6 = target->family == AF_INET6;
    int length = snprintf(buffer, buffer_size, "HEAD / HTTP/1.0\r\nHost: %s%s%s\r\n\r\n", v6 ? "[" : "",
                          target->ip_text, v6 ? "]" : "");
    if (length <= 0 || (size_t)length >= buffer_size) {
        return 0;
    }
    return (size_t)length;
}

/* Ports where the client starts with a TLS handshake. */
static bool is_tls_port(uint16_t port)
{
    static const uint16_t tls_ports[] = {443, 465, 636, 853, 990, 993, 995, 5061, 6697, 8443, 9443};
    for (size_t i = 0; i < sizeof tls_ports / sizeof tls_ports[0]; i++) {
        if (tls_ports[i] == port) {
            return true;
        }
    }
    return false;
}

static probe_kind first_probe(uint16_t port)
{
    if (is_http_port(port)) {
        return PROBE_HTTP;
    }
    if (is_tls_port(port)) {
        return PROBE_TLS;
    }
    if (port == 5432 || port == 5433) {
        return PROBE_PGSQL;
    }
    return PROBE_GREETING;
}

static size_t build_probe(probe_kind kind, const scan_target *target, unsigned char *buffer, size_t size)
{
    switch (kind) {
    case PROBE_HTTP:
        return http_head_request(target, (char *)buffer, size);
    case PROBE_TLS:
        return tls_client_hello(buffer, size);
    case PROBE_PGSQL:
        return pgsql_ssl_request(buffer, size);
    case PROBE_GREETING:
        break;
    }
    return 0;
}

static bool contains(const unsigned char *data, size_t length, const char *needle, size_t needle_length)
{
    for (size_t i = 0; i + needle_length <= length; i++) {
        if (memcmp(data + i, needle, needle_length) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Should we wait for more bytes? A reply can arrive in several TCP segments;
 * read on only while a message we can parse is visibly unfinished.
 */
static bool reply_incomplete(const unsigned char *reply, size_t length)
{
    if (length >= 5 && (memcmp(reply, "HTTP/", 5) == 0 || memcmp(reply, "RTSP/", 5) == 0)) {
        return !contains(reply, length, "\r\n\r\n", 4) && !contains(reply, length, "\n\n", 2);
    }
    if (length >= 4 && memcmp(reply, "SSH-", 4) == 0) {
        return !contains(reply, length, "\n", 1);
    }
    if (length >= 2 && reply[0] == 0x16 && reply[1] == 0x03) {
        /* TLS: we only need the first handshake message (the ServerHello). */
        if (length < 9) {
            return true;
        }
        size_t needed = 9 + ((size_t)reply[6] << 16 | (size_t)reply[7] << 8 | reply[8]);
        return length < needed;
    }
    return false;
}

/*
 * Worth showing as a banner? The start of the first line must be printable
 * text: a MySQL greeting starts with a length byte that happens to be a
 * letter, followed by binary data.
 */
static bool looks_like_text(const unsigned char *reply, size_t length)
{
    size_t checked = 0;
    for (; checked < length && checked < 16; checked++) {
        unsigned char c = reply[checked];
        if (c == '\r' || c == '\n') {
            break;
        }
        if (c < 0x20 || c >= 0x7f) {
            return false;
        }
    }
    return checked > 0;
}

/* Send a probe (none for PROBE_GREETING) and collect the reply. Returns the number of bytes received. */
static size_t exchange(int fd, const unsigned char *probe, size_t probe_length, int wait_ms, unsigned char *reply,
                       size_t reply_size)
{
    if (probe_length > 0 && send(fd, probe, probe_length, MSG_NOSIGNAL) != (ssize_t)probe_length) {
        return 0;
    }
    double deadline_ms = monotonic_time_ms() + wait_ms;
    size_t received = 0;
    while (received < reply_size && wait_for_data(fd, deadline_ms)) {
        ssize_t count = recv(fd, reply + received, reply_size - received, 0);
        if (count <= 0) {
            break; /* the service closed the connection (or an error) */
        }
        received += (size_t)count;
        if (!reply_incomplete(reply, received)) {
            break;
        }
    }
    return received;
}

void detect_tcp_service(const scan_target *target, int connected_fd, const scan_settings *settings,
                        port_result *result)
{
    probe_kind plan[MAX_PROBES];
    size_t steps = 0;
    plan[steps++] = first_probe(result->port);
    if (plan[0] != PROBE_TLS) {
        plan[steps++] = PROBE_TLS;
    }
    if (plan[0] != PROBE_HTTP) {
        plan[steps++] = PROBE_HTTP;
    }

    int wait_ms = service_wait_ms(settings->timeout_ms);
    int fd = connected_fd;
    for (size_t step = 0; step < steps && !scan_stop_requested(); step++) {
        if (step > 0) {
            fd = connect_tcp_port(target, result->port, settings->timeout_ms);
            if (fd == -1) {
                break; /* the port stopped accepting connections */
            }
        }
        unsigned char probe[PROBE_MAX];
        unsigned char reply[REPLY_MAX];
        size_t probe_length = build_probe(plan[step], target, probe, sizeof probe);
        size_t received = exchange(fd, probe, probe_length, wait_ms, reply, sizeof reply);
        close(fd);
        fd = -1;

        /*
         * Keep the first text reply to a greeting or HEAD as banner. Replies to the
         * binary probes (TLS, PostgreSQL) often echo the probe bytes back.
         */
        bool text_probe = plan[step] == PROBE_GREETING || plan[step] == PROBE_HTTP;
        if (text_probe && result->banner[0] == '\0' && looks_like_text(reply, received)) {
            sanitize_banner((const char *)reply, received, result->banner, sizeof result->banner);
        }
        service_info info;
        if (identify_tcp_reply(plan[step], reply, received, &info)) {
            result->detected = malloc(sizeof *result->detected);
            if (result->detected != NULL) {
                *result->detected = info;
            }
            return;
        }
        if (received > 0 && plan[step] == PROBE_GREETING) {
            return; /* it spoke first, in a protocol Janus does not know: do not poke it further */
        }
    }
    if (fd != -1) {
        close(fd); /* only if the loop never ran (stop requested) */
    }
}
