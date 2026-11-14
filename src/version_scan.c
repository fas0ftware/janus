#include "version_scan.h"

#include <stdio.h>      /* snprintf */
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memcmp, strcmp, strstr */
#include <sys/socket.h> /* send, recv */
#include <unistd.h>     /* close */

#include "fingerprint.h"
#include "utils.h"

/* Bytes kept per reply: HTTP headers, or a TLS ServerHello plus the server's certificate. */
#define REPLY_MAX 16384
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
        return tls_client_hello(buffer, size, target->host_name, false);
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
        return !tls_reply_complete(reply, length); /* ServerHello, plus the certificate below TLS 1.3 */
    }
    if (length >= 4 && reply[0] >= '0' && reply[0] <= '9' && reply[3] == '-') {
        return !line_reply_complete(reply, length); /* "220-..." multi-line FTP/SMTP greeting */
    }
    return false;
}

/* When to stop reading a reply. */
typedef enum {
    UNTIL_PARSED, /* the reply_incomplete() rules above */
    UNTIL_LINE,   /* one line, or a whole multi-line "250-..." SMTP/FTP reply */
    UNTIL_TAGGED, /* the IMAP line tagged with IMAP_TAG */
} reply_end;

#define IMAP_TAG "J1"

static bool reply_done(reply_end end, const unsigned char *reply, size_t length)
{
    switch (end) {
    case UNTIL_LINE:
        return line_reply_complete(reply, length);
    case UNTIL_TAGGED:
        return tagged_reply_complete(reply, length, IMAP_TAG);
    case UNTIL_PARSED:
        break;
    }
    return !reply_incomplete(reply, length);
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

/* Send a probe (may be empty) and collect the reply until `end` says it is complete. Returns its length. */
static size_t converse(int fd, const void *probe, size_t probe_length, reply_end end, int wait_ms,
                       unsigned char *reply, size_t reply_size)
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
        if (reply_done(end, reply, received)) {
            break;
        }
    }
    return received;
}

static size_t exchange(int fd, const unsigned char *probe, size_t probe_length, int wait_ms, unsigned char *reply,
                       size_t reply_size)
{
    return converse(fd, probe, probe_length, UNTIL_PARSED, wait_ms, reply, reply_size);
}

static bool starts_with(const unsigned char *reply, size_t length, const char *prefix)
{
    size_t prefix_length = strlen(prefix);
    return length >= prefix_length && memcmp(reply, prefix, prefix_length) == 0;
}

/* Services whose plaintext protocol has a command that switches the connection to TLS. */
static bool has_starttls(const char *service)
{
    static const char *const services[] = {"smtp", "imap", "pop3", "ftp", "postgresql"};
    for (size_t i = 0; i < sizeof services / sizeof services[0]; i++) {
        if (strcmp(service, services[i]) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Talk the service into TLS on a fresh connection:
 *
 *   smtp        greeting, EHLO (must list STARTTLS), STARTTLS -> 220
 *   imap        greeting, J1 STARTTLS -> J1 OK
 *   pop3        greeting, STLS -> +OK
 *   ftp         greeting, AUTH TLS -> 234
 *   postgresql  SSLRequest -> 'S'
 *
 * Returns true when the server agreed; the connection then expects a ClientHello.
 * The EHLO name "janus.invalid" uses the reserved .invalid domain: it says
 * nothing about the machine Janus runs on.
 */
static bool request_tls_upgrade(int fd, const char *service, int wait_ms)
{
    unsigned char reply[2048];
    size_t length = 0;
    if (strcmp(service, "postgresql") == 0) {
        unsigned char request[8];
        size_t request_length = pgsql_ssl_request(request, sizeof request);
        length = converse(fd, request, request_length, UNTIL_PARSED, wait_ms, reply, 1);
        return length == 1 && reply[0] == 'S';
    }
    if (converse(fd, NULL, 0, UNTIL_LINE, wait_ms, reply, sizeof reply) == 0) {
        return false; /* no greeting this time */
    }
    if (strcmp(service, "smtp") == 0) {
        static const char ehlo[] = "EHLO janus.invalid\r\n";
        length = converse(fd, ehlo, sizeof ehlo - 1, UNTIL_LINE, wait_ms, reply, sizeof reply);
        if (!smtp_offers_starttls(reply, length)) {
            return false;
        }
        static const char starttls[] = "STARTTLS\r\n";
        length = converse(fd, starttls, sizeof starttls - 1, UNTIL_LINE, wait_ms, reply, sizeof reply);
        return starts_with(reply, length, "220");
    }
    if (strcmp(service, "imap") == 0) {
        static const char starttls[] = IMAP_TAG " STARTTLS\r\n";
        length = converse(fd, starttls, sizeof starttls - 1, UNTIL_TAGGED, wait_ms, reply, sizeof reply);
        /* Untagged lines may come first; the tagged line is the answer. */
        for (size_t i = 0; i + 6 <= length; i++) {
            if ((i == 0 || reply[i - 1] == '\n') && memcmp(reply + i, IMAP_TAG " OK", 5) == 0) {
                return true;
            }
        }
        return false;
    }
    if (strcmp(service, "pop3") == 0) {
        static const char stls[] = "STLS\r\n";
        length = converse(fd, stls, sizeof stls - 1, UNTIL_LINE, wait_ms, reply, sizeof reply);
        return starts_with(reply, length, "+OK");
    }
    if (strcmp(service, "ftp") == 0) {
        static const char auth[] = "AUTH TLS\r\n";
        length = converse(fd, auth, sizeof auth - 1, UNTIL_LINE, wait_ms, reply, sizeof reply);
        return starts_with(reply, length, "234");
    }
    return false;
}

/*
 * One STARTTLS attempt on a new connection. Returns STARTTLS_OK and fills *tls
 * when the upgrade worked and a TLS reply came back, STARTTLS_NOT_OFFERED when
 * the server declined, STARTTLS_NOT_APPLICABLE when it could not be asked
 * (no connection, Ctrl+C).
 */
static starttls_state starttls_probe(const scan_target *target, uint16_t port, const char *service,
                                     bool tls12_only, const scan_settings *settings, service_info *tls)
{
    if (scan_stop_requested()) {
        return STARTTLS_NOT_APPLICABLE;
    }
    int fd = connect_tcp_port(target, port, settings->timeout_ms);
    if (fd == -1) {
        return STARTTLS_NOT_APPLICABLE;
    }
    int wait_ms = service_wait_ms(settings->timeout_ms);
    starttls_state state = STARTTLS_NOT_OFFERED;
    if (request_tls_upgrade(fd, service, wait_ms)) {
        unsigned char probe[PROBE_MAX];
        unsigned char reply[REPLY_MAX];
        size_t probe_length = tls_client_hello(probe, sizeof probe, target->host_name, tls12_only);
        size_t received = exchange(fd, probe, probe_length, wait_ms, reply, sizeof reply);
        if (identify_tcp_reply(PROBE_TLS, reply, received, tls) && strcmp(tls->service, "tls") == 0) {
            state = STARTTLS_OK;
        } else {
            state = STARTTLS_NOT_APPLICABLE; /* agreed, then no usable TLS answer: do not claim either way */
        }
    } else if (scan_stop_requested()) {
        state = STARTTLS_NOT_APPLICABLE;
    }
    close(fd);
    return state;
}

/* Mail, FTP and PostgreSQL: is TLS offered, which version, which certificate? */
static void check_starttls(const scan_target *target, uint16_t port, const scan_settings *settings,
                           service_info *info)
{
    if (strcmp(info->service, "postgresql") == 0 && strcmp(info->info, "TLS not offered") == 0) {
        info->starttls_status = STARTTLS_NOT_OFFERED; /* it already said 'N' to the SSLRequest */
        return;
    }
    service_info tls;
    info->starttls_status = starttls_probe(target, port, info->service, false, settings, &tls);
    if (info->starttls_status != STARTTLS_OK) {
        return;
    }
    memcpy(info->starttls, tls.info, sizeof info->starttls);
    info->certificate = tls.certificate;
    if (!tls.certificate.present && strstr(tls.info, "TLS 1.3") != NULL &&
        starttls_probe(target, port, info->service, true, settings, &tls) == STARTTLS_OK) {
        info->certificate = tls.certificate; /* the TLS 1.2 handshake shows it in clear text */
    }
}

/*
 * TLS 1.3 encrypts the certificate. Ask once more offering only TLS 1.2,
 * where it travels in clear text. A server that accepts nothing older than
 * 1.3 answers with an alert, and the certificate stays unknown.
 */
static void fetch_tls12_certificate(const scan_target *target, uint16_t port, const scan_settings *settings,
                                    tls_certificate *certificate)
{
    if (scan_stop_requested()) {
        return;
    }
    int fd = connect_tcp_port(target, port, settings->timeout_ms);
    if (fd == -1) {
        return;
    }
    unsigned char probe[PROBE_MAX];
    unsigned char reply[REPLY_MAX];
    size_t probe_length = tls_client_hello(probe, sizeof probe, target->host_name, true);
    size_t received = exchange(fd, probe, probe_length, service_wait_ms(settings->timeout_ms), reply, sizeof reply);
    close(fd);
    service_info info;
    if (identify_tcp_reply(PROBE_TLS, reply, received, &info) && info.certificate.present) {
        *certificate = info.certificate;
    }
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
            if (strcmp(info.service, "tls") == 0 && !info.certificate.present && strstr(info.info, "TLS 1.3")) {
                fetch_tls12_certificate(target, result->port, settings, &info.certificate);
            } else if (has_starttls(info.service)) {
                check_starttls(target, result->port, settings, &info);
            }
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
