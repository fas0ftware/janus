#ifndef JANUS_SCANNER_H
#define JANUS_SCANNER_H

/*
 * Include guard: if this header is included twice in the same .c file,
 * the second copy is skipped, so types are not defined twice.
 */

#include <netinet/in.h> /* INET6_ADDRSTRLEN */
#include <sys/socket.h> /* struct sockaddr_storage, socklen_t */
#include <stdbool.h>    /* bool */
#include <stddef.h>     /* size_t */
#include <stdint.h>     /* uint16_t */

/* Possible results of scanning one port. */
typedef enum {
    PORT_NOT_SCANNED, /* scan was stopped before reaching this port */
    PORT_OPEN,        /* the target completed the TCP handshake (SYN-ACK) */
    PORT_CLOSED,      /* the target answered with RST: "connection refused" */
    PORT_FILTERED,    /* no answer before the timeout (likely a firewall) */
    PORT_ERROR        /* a local error prevented the check */
} port_state;

/* Longest banner kept per port (first line only, printable ASCII). */
#define BANNER_SIZE 96

/* Result for one port. */
typedef struct {
    uint16_t port;
    port_state state;
    int error_code;           /* errno value when state == PORT_ERROR, otherwise 0 */
    char banner[BANNER_SIZE]; /* "" unless --banner found one on an open port */
} port_result;

/* Which address family resolve_target may return. */
typedef enum { FAMILY_ANY, FAMILY_IPV4, FAMILY_IPV6 } address_family;

/* A resolved target: the binary address (IPv4 or IPv6) plus a printable IP string. */
typedef struct {
    struct sockaddr_storage address;
    socklen_t address_length;
    int family; /* AF_INET or AF_INET6 */
    char ip_text[INET6_ADDRSTRLEN];
} scan_target;

/* How to scan: shared by all worker threads, never changed during a scan. */
typedef struct {
    int timeout_ms;
    int thread_count;
    bool grab_banner; /* read a short greeting from open ports */
} scan_settings;

/* Resolve a host name, IPv4 or IPv6 address once, before scanning. Returns 0 on success. */
int resolve_target(const char *host, address_family family, scan_target *target);

/* Scan one port: non-blocking connect that waits at most timeout_ms. */
port_result scan_port(const scan_target *target, uint16_t port, const scan_settings *settings);

/*
 * One host in a multi-host scan. target == NULL means "skip" (e.g. the name
 * could not be resolved). finished_ms is filled in: the monotonic time when
 * the last of this host's ports was done (0 if none was scanned).
 */
typedef struct {
    const scan_target *target;
    port_result *results; /* ports_per_host entries, each .port set */
    double finished_ms;
} host_job;

/*
 * Scan all hosts with ONE shared pool of thread_count workers. The work queue
 * holds every (host, port) pair, so with a CIDR block the workers are never
 * idle waiting for a single slow host: silent addresses are probed in
 * parallel instead of one after another. Returns 0, or -1 on a setup error.
 */
int scan_hosts(host_job *hosts, size_t host_count, size_t ports_per_host,
               const scan_settings *settings);

/*
 * Scan every port in results[0..count-1] (each .port must be set).
 * Each entry's state is filled in. Returns 0, or -1 on a setup error.
 */
int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    const scan_settings *settings);

/*
 * Keep the first line of raw service output as printable ASCII (other bytes
 * become '.'), trimmed, at most out_size - 1 characters. Exposed for tests.
 */
void sanitize_banner(const char *raw, size_t raw_length, char *out, size_t out_size);

/*
 * Ask all running scans to stop as soon as possible (used for Ctrl+C).
 * Async-signal-safe: may be called from a signal handler.
 */
void request_scan_stop(void);

/* True once request_scan_stop() has been called. */
bool scan_stop_requested(void);

/* Turn a port_state into a printable word such as "open". */
const char *port_state_to_string(port_state state);

#endif /* JANUS_SCANNER_H */
