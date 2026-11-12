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
    PORT_ERROR,       /* a local error prevented the check */
    PORT_OPEN_FILTERED /* UDP only: no reply and no ICMP error, so open or filtered */
} port_state;

/* Which transport protocol a scan uses. */
typedef enum { PROTOCOL_TCP, PROTOCOL_UDP } scan_protocol;

/* Whether a host answered during --discover. */
typedef enum {
    HOST_STATUS_UNKNOWN, /* discovery was not run, or the host could not be resolved */
    HOST_UP,             /* at least one probe port answered (open or closed) */
    HOST_DOWN            /* no probe port answered: the host is skipped */
} host_status;

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
    bool grab_banner; /* read a short greeting from open ports (TCP only) */
    scan_protocol protocol;
} scan_settings;

/* Resolve a host name, IPv4 or IPv6 address once, before scanning. Returns 0 on success. */
int resolve_target(const char *host, address_family family, scan_target *target);

/*
 * Scan one port and wait at most timeout_ms: a non-blocking connect for TCP,
 * a datagram probe for UDP (see udp_scan.h).
 */
port_result scan_port(const scan_target *target, uint16_t port, const scan_settings *settings);

/*
 * Scan every port in results[0..count-1] (each .port must be set).
 * Each entry's state is filled in. Returns 0, or -1 on a setup error.
 */
int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    const scan_settings *settings);

/*
 * Scan the ports of many hosts with ONE pool of settings->thread_count workers.
 *
 * results holds host_count blocks of ports_per_host entries (host-major: the
 * ports of host h are results[h * ports_per_host ...], each .port must be set).
 * Only hosts with scan_host[h] == true are scanned. All (host, port) pairs go
 * into a single queue, so workers never idle just because one host has fewer
 * ports than there are threads. Hosts are started in order, so after Ctrl+C
 * the scanned hosts are (nearly) a prefix of the list.
 *
 * host_ms[h] receives how long host h took, from its first port being started
 * to its last port finishing (0 if it was not scanned or not finished).
 * Returns 0, or -1 on a setup error.
 */
int scan_host_ports(const scan_target *targets, const bool *scan_host, size_t host_count,
                    port_result *results, size_t ports_per_host, const scan_settings *settings,
                    double *host_ms);

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
