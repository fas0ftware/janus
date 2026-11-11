#ifndef JANUS_SCANNER_H
#define JANUS_SCANNER_H

/*
 * Include guard: if this header is included twice in the same .c file,
 * the second copy is skipped, so types are not defined twice.
 */

/* Possible results of scanning one port. */
typedef enum {
    PORT_OPEN,   /* the target completed the TCP handshake (SYN-ACK) */
    PORT_CLOSED, /* the target answered with RST: "connection refused" */
    PORT_ERROR   /* something else failed (name lookup, no route, ...) */
} port_state;

/* Try a full TCP connect to host:port and report what happened. Blocking. */
port_state scan_port(const char *host, int port);

/* Turn a port_state into a printable word such as "open". */
const char *port_state_to_string(port_state state);

#endif /* JANUS_SCANNER_H */
