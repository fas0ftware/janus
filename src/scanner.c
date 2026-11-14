#include "scanner.h"

#include <arpa/inet.h>  /* inet_ntop, htons */
#include <errno.h>      /* errno, EINPROGRESS, ECONNREFUSED, ... */
#include <fcntl.h>      /* fcntl, O_NONBLOCK */
#include <netdb.h>      /* getaddrinfo, freeaddrinfo, gai_strerror */
#include <poll.h>       /* poll, struct pollfd */
#include <pthread.h>    /* pthread_create, pthread_join */
#include <stdatomic.h>  /* atomic_bool, atomic_size_t, atomic_llong, atomic_fetch_add */
#include <stdbool.h>    /* bool */
#include <stdio.h>      /* snprintf */
#include <stdlib.h>     /* calloc, free */
#include <string.h>     /* memset, memcpy, strerror */
#include <sys/socket.h> /* socket, connect, getsockopt */
#include <unistd.h>     /* close */

#include "udp_scan.h"
#include "version_scan.h"
#include "utils.h"

/* Longest single poll() wait, so a stop request is noticed quickly. */
#define POLL_SLICE_MS 100

/*
 * Set by the Ctrl+C signal handler, read by every worker thread.
 * A plain bool would be a data race (two threads, one writes, no lock).
 * An atomic variable is safe both across threads and inside a signal
 * handler, because reads and writes happen as one indivisible step.
 */
static atomic_bool stop_requested = false;

void request_scan_stop(void)
{
    atomic_store(&stop_requested, true);
}

bool scan_stop_requested(void)
{
    return atomic_load(&stop_requested);
}

int resolve_target(const char *host, address_family family, scan_target *target)
{
    /* hints tells getaddrinfo what kind of address we want back. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); /* start with every field zeroed */
    hints.ai_family = family == FAMILY_IPV4 ? AF_INET : family == FAMILY_IPV6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; /* stream socket = TCP */

    struct addrinfo *results = NULL;
    int lookup_result = getaddrinfo(host, NULL, &hints, &results);
    if (lookup_result != 0) {
        print_error("cannot resolve '%s': %s", host, gai_strerror(lookup_result));
        return -1;
    }

    /*
     * With AF_UNSPEC a name can resolve to both families. Prefer IPv4 (the
     * common case on home networks), fall back to the first IPv6 address.
     */
    const struct addrinfo *chosen = results;
    for (const struct addrinfo *item = results; item != NULL; item = item->ai_next) {
        if (item->ai_family == AF_INET) {
            chosen = item;
            break;
        }
    }
    if ((chosen->ai_family != AF_INET && chosen->ai_family != AF_INET6) ||
        chosen->ai_addrlen > sizeof target->address) {
        print_error("unsupported address for '%s'", host);
        freeaddrinfo(results);
        return -1;
    }

    /* Copy the address so the list can be freed right away. */
    memset(target, 0, sizeof *target);
    memcpy(&target->address, chosen->ai_addr, chosen->ai_addrlen);
    target->address_length = chosen->ai_addrlen;
    target->family = chosen->ai_family;
    freeaddrinfo(results);

    /* Binary address -> "127.0.0.1" or "::1" for display. */
    const void *raw = target->family == AF_INET
                          ? (const void *)&((const struct sockaddr_in *)&target->address)->sin_addr
                          : (const void *)&((const struct sockaddr_in6 *)&target->address)->sin6_addr;
    if (inet_ntop(target->family, raw, target->ip_text, sizeof target->ip_text) == NULL) {
        print_error("cannot format address of '%s'", host);
        return -1;
    }
    return 0;
}

/* Put the socket into non-blocking mode so connect() returns immediately. */
static int set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0); /* read the current flags first ... */
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK); /* ... then add one flag */
}

/* Map a connect error (errno or SO_ERROR value) to a port state. */
static port_state classify_connect_error(int error_code)
{
    switch (error_code) {
    case 0:
        return PORT_OPEN;
    case ECONNREFUSED: /* RST received */
        return PORT_CLOSED;
    case ETIMEDOUT:    /* kernel gave up waiting */
    case EHOSTUNREACH: /* ICMP "host unreachable", often sent by firewalls */
        return PORT_FILTERED;
    default:
        return PORT_ERROR;
    }
}

/*
 * Start a TCP handshake and wait at most timeout_ms for it to finish.
 * On PORT_ERROR the errno value is stored in *error_code.
 */
static port_state connect_with_timeout(const struct sockaddr *address, socklen_t address_length,
                                       int timeout_ms, int *error_code, int *open_fd)
{
    *error_code = 0;
    *open_fd = -1;

    int fd = socket(address->sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        *error_code = errno;
        return PORT_ERROR;
    }

    if (set_non_blocking(fd) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }

    /*
     * Non-blocking connect: the kernel sends the SYN and returns at once.
     * EINPROGRESS means "handshake started, result comes later".
     */
    if (connect(fd, address, address_length) == 0) {
        *open_fd = fd; /* connected instantly (can happen on localhost) */
        return PORT_OPEN;
    }
    if (errno != EINPROGRESS) {
        int connect_error = errno; /* save it: close() may change errno */
        port_state state = classify_connect_error(connect_error);
        if (state == PORT_ERROR) {
            *error_code = connect_error;
        }
        close(fd);
        return state;
    }

    /*
     * Wait until the socket becomes writable (handshake finished, either
     * way) or until the timeout expires. Instead of one long poll() we wait
     * in short slices, so a Ctrl+C is noticed within POLL_SLICE_MS even
     * when the timeout is long.
     */
    struct pollfd watch = {.fd = fd, .events = POLLOUT, .revents = 0};
    double deadline_ms = monotonic_time_ms() + timeout_ms;
    for (;;) {
        if (scan_stop_requested()) {
            close(fd);
            return PORT_NOT_SCANNED;
        }
        double remaining_ms = deadline_ms - monotonic_time_ms();
        if (remaining_ms <= 0) {
            close(fd);
            return PORT_FILTERED; /* silence: no SYN-ACK and no RST */
        }
        int wait_ms = remaining_ms > POLL_SLICE_MS ? POLL_SLICE_MS : (int)remaining_ms + 1;

        int ready = poll(&watch, 1, wait_ms);
        if (ready > 0) {
            break; /* handshake finished, result is read below */
        }
        if (ready == -1 && errno != EINTR) {
            *error_code = errno;
            close(fd);
            return PORT_ERROR;
        }
        /* ready == 0 (slice over) or EINTR (a signal arrived): loop again */
    }

    /* The socket is "ready", but did the handshake succeed? Ask the kernel. */
    int socket_error = 0;
    socklen_t length = sizeof socket_error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }

    port_state state = classify_connect_error(socket_error);
    if (state == PORT_ERROR) {
        *error_code = socket_error;
    }
    if (state == PORT_OPEN) {
        *open_fd = fd; /* the caller may read a banner, then closes it */
    } else {
        close(fd);
    }
    return state;
}

void sanitize_banner(const char *raw, size_t raw_length, char *out, size_t out_size)
{
    if (out_size == 0) {
        return;
    }
    size_t start = 0;
    while (start < raw_length && (raw[start] == ' ' || raw[start] == '\r' || raw[start] == '\n' ||
                                  raw[start] == '\t')) {
        start++; /* skip leading blank lines */
    }
    size_t written = 0;
    for (size_t i = start; i < raw_length && written + 1 < out_size; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\r' || c == '\n' || c == '\0') {
            break; /* first line only */
        }
        /* Untrusted bytes: never pass terminal escapes or non-ASCII through. */
        out[written++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    while (written > 0 && out[written - 1] == ' ') {
        written--;
    }
    out[written] = '\0';
}

bool is_http_port(uint16_t port)
{
    static const uint16_t http_ports[] = {80, 591, 631, 3000, 5000, 8000, 8008, 8080, 8081, 8888};
    for (size_t i = 0; i < sizeof http_ports / sizeof http_ports[0]; i++) {
        if (http_ports[i] == port) {
            return true;
        }
    }
    return false;
}

bool wait_for_data(int fd, double deadline_ms)
{
    struct pollfd watch = {.fd = fd, .events = POLLIN, .revents = 0};
    for (;;) {
        double remaining_ms = deadline_ms - monotonic_time_ms();
        if (remaining_ms <= 0 || scan_stop_requested()) {
            return false;
        }
        int wait_ms = remaining_ms > POLL_SLICE_MS ? POLL_SLICE_MS : (int)remaining_ms + 1;
        int ready = poll(&watch, 1, wait_ms);
        if (ready > 0) {
            return true;
        }
        if (ready == -1 && errno != EINTR) {
            return false;
        }
    }
}

/*
 * Many services greet first (SSH, FTP, SMTP, POP3, IMAP, MySQL...). Wait a
 * moment for that greeting; on common HTTP ports send a minimal HEAD
 * request instead and keep the status line. Nothing else is ever sent.
 */
static void read_banner(int fd, const scan_target *target, uint16_t port, int timeout_ms, char *banner,
                        size_t banner_size)
{
    banner[0] = '\0';
    int budget_ms = service_wait_ms(timeout_ms);
    if (is_http_port(port)) {
        char probe[HTTP_REQUEST_MAX];
        size_t length = http_head_request(target, probe, sizeof probe);
        if (length == 0 || send(fd, probe, length, MSG_NOSIGNAL) != (ssize_t)length) {
            return;
        }
    }
    if (!wait_for_data(fd, monotonic_time_ms() + budget_ms)) {
        return;
    }
    char raw[512];
    ssize_t received = recv(fd, raw, sizeof raw, 0);
    if (received > 0) {
        sanitize_banner(raw, (size_t)received, banner, banner_size);
    }
}

/* Copy the resolved address and fill in the port for this attempt. */
static struct sockaddr_storage address_with_port(const scan_target *target, uint16_t port)
{
    struct sockaddr_storage address = target->address;
    if (target->family == AF_INET) {
        ((struct sockaddr_in *)&address)->sin_port = htons(port); /* host -> network byte order */
    } else {
        ((struct sockaddr_in6 *)&address)->sin6_port = htons(port);
    }
    return address;
}

int connect_tcp_port(const scan_target *target, uint16_t port, int timeout_ms)
{
    struct sockaddr_storage address = address_with_port(target, port);
    int error_code = 0;
    int fd = -1;
    connect_with_timeout((const struct sockaddr *)&address, target->address_length, timeout_ms, &error_code, &fd);
    return fd;
}

port_result scan_port(const scan_target *target, uint16_t port, const scan_settings *settings)
{
    if (settings->protocol == PROTOCOL_UDP) {
        return scan_udp_port(target, port, settings);
    }
    struct sockaddr_storage address = address_with_port(target, port);

    port_result result = {.port = port, .state = PORT_NOT_SCANNED, .error_code = 0, .banner = "", .detected = NULL};
    int open_fd = -1;
    result.state = connect_with_timeout((const struct sockaddr *)&address, target->address_length,
                                        settings->timeout_ms, &result.error_code, &open_fd);
    if (open_fd != -1) {
        if (settings->detect_version) {
            detect_tcp_service(target, open_fd, settings, &result); /* closes open_fd */
        } else {
            if (settings->grab_banner) {
                read_banner(open_fd, target, port, settings->timeout_ms, result.banner, sizeof result.banner);
            }
            close(open_fd);
        }
    }
    return result;
}

void free_port_details(port_result *results, size_t count)
{
    if (results == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(results[i].detected);
        results[i].detected = NULL;
    }
}

/*
 * Shared work queue over every (host, port) pair.
 *
 * Jobs are numbered host-major: job j is port (j % ports_per_host) of host
 * (j / ports_per_host), which is also the index of its slot in results. Each
 * worker claims job numbers with an atomic fetch_add, so every job goes to
 * exactly one thread and no mutex is needed. Each worker writes only the
 * slots it claimed.
 */
typedef struct {
    const scan_target *targets;
    const bool *scan_host;
    size_t host_count;
    port_result *results;
    size_t ports_per_host;
    size_t job_count;
    const scan_settings *settings;
    atomic_size_t next_job;
    atomic_size_t *remaining;  /* per host: ports not finished yet */
    atomic_llong *started_us;  /* per host: monotonic microseconds when its first port started */
    double *host_ms;           /* per host: written once, by the thread that finishes its last port */
} scan_queue;

/* Thread body: keep claiming jobs until none are left or Ctrl+C was pressed. */
static void *scan_worker(void *argument)
{
    scan_queue *queue = argument;

    while (!scan_stop_requested()) {
        size_t job = atomic_fetch_add(&queue->next_job, 1);
        if (job >= queue->job_count) {
            break;
        }
        size_t host = job / queue->ports_per_host;
        if (!queue->scan_host[host]) {
            continue; /* unresolved, or down according to --discover */
        }
        if (job % queue->ports_per_host == 0) {
            /* The first port of a host is always claimed first, by exactly one thread. */
            atomic_store(&queue->started_us[host], (long long)(monotonic_time_ms() * 1000.0));
        }

        port_result *slot = &queue->results[job];
        *slot = scan_port(&queue->targets[host], slot->port, queue->settings);

        /* The thread that finishes the host's last port records how long the host took. */
        if (atomic_fetch_sub(&queue->remaining[host], 1) == 1) {
            queue->host_ms[host] = monotonic_time_ms() - (double)atomic_load(&queue->started_us[host]) / 1000.0;
        }
    }
    return NULL;
}

int scan_host_ports(const scan_target *targets, const bool *scan_host, size_t host_count,
                    port_result *results, size_t ports_per_host, const scan_settings *settings,
                    double *host_ms)
{
    size_t scanned_hosts = 0;
    for (size_t h = 0; h < host_count; h++) {
        host_ms[h] = 0.0;
        scanned_hosts += scan_host[h];
    }
    if (ports_per_host == 0 || scanned_hosts == 0) {
        return 0;
    }

    scan_queue queue = {
        .targets = targets,
        .scan_host = scan_host,
        .host_count = host_count,
        .results = results,
        .ports_per_host = ports_per_host,
        .job_count = host_count * ports_per_host,
        .settings = settings,
        .host_ms = host_ms,
    };
    atomic_init(&queue.next_job, 0);
    queue.remaining = calloc(host_count, sizeof *queue.remaining);
    queue.started_us = calloc(host_count, sizeof *queue.started_us);
    /* More threads than ports to scan would only sit idle. */
    size_t wanted = (size_t)settings->thread_count;
    if (wanted > scanned_hosts * ports_per_host) {
        wanted = scanned_hosts * ports_per_host;
    }
    pthread_t *threads = calloc(wanted, sizeof *threads);
    if (queue.remaining == NULL || queue.started_us == NULL || threads == NULL) {
        print_error("out of memory");
        free(queue.remaining);
        free(queue.started_us);
        free(threads);
        return -1;
    }
    for (size_t h = 0; h < host_count; h++) {
        atomic_init(&queue.remaining[h], ports_per_host);
        atomic_init(&queue.started_us[h], 0);
    }

    size_t started = 0;
    for (size_t i = 0; i < wanted; i++) {
        int error = pthread_create(&threads[i], NULL, scan_worker, &queue);
        if (error != 0) {
            /* Not fatal: the threads already running will share the work. */
            print_error("could only start %zu of %zu threads: %s", started, wanted, strerror(error));
            break;
        }
        started++;
    }

    if (started == 0) {
        scan_worker(&queue); /* no threads at all: do the work ourselves */
    }

    /* Wait for every worker to finish before the results are read. */
    for (size_t i = 0; i < started; i++) {
        int error = pthread_join(threads[i], NULL);
        if (error != 0) {
            print_error("cannot join worker thread: %s", strerror(error));
        }
    }

    free(threads);
    free(queue.remaining);
    free(queue.started_us);
    return 0;
}

int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    const scan_settings *settings)
{
    const bool scan_it = true;
    double duration_ms = 0.0;
    return scan_host_ports(target, &scan_it, 1, results, count, settings, &duration_ms);
}

const char *port_state_to_string(port_state state)
{
    switch (state) {
    case PORT_NOT_SCANNED:
        return "not-scanned";
    case PORT_OPEN:
        return "open";
    case PORT_CLOSED:
        return "closed";
    case PORT_FILTERED:
        return "filtered";
    case PORT_ERROR:
        return "error";
    case PORT_OPEN_FILTERED:
        return "open|filtered";
    }
    return "unknown"; /* unreachable, but keeps the compiler happy */
}
