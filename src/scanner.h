#ifndef JANUS_SCANNER_H
#define JANUS_SCANNER_H

/*
 * Include guard: if this header is included twice in the same .c file,
 * the second copy is skipped, so types are not defined twice.
 */

#include <netinet/in.h> /* struct sockaddr_in, INET_ADDRSTRLEN */
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

/* Result for one port. */
typedef struct {
    uint16_t port;
    port_state state;
    int error_code; /* errno value when state == PORT_ERROR, otherwise 0 */
} port_result;

/* A resolved target: the binary address plus a printable IP string. */
typedef struct {
    struct sockaddr_in address;
    char ip_text[INET_ADDRSTRLEN];
} scan_target;

/* Resolve a host name or IPv4 address once, before scanning. Returns 0 on success. */
int resolve_target(const char *host, scan_target *target);

/* Scan one port: non-blocking connect that waits at most timeout_ms. */
port_result scan_port(const scan_target *target, uint16_t port, int timeout_ms);

/*
 * Scan every port in results[0..count-1] (each .port must be set).
 * Each entry's state is filled in. Returns 0, or -1 on a setup error.
 */
int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    int timeout_ms, int thread_count);

/* Turn a port_state into a printable word such as "open". */
const char *port_state_to_string(port_state state);

#endif /* JANUS_SCANNER_H */
