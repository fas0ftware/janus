#ifndef JANUS_SERVICES_H
#define JANUS_SERVICES_H

#include <stdint.h> /* uint16_t */

/*
 * Return the well-known service name for a port ("ssh" for 22 with protocol
 * "tcp", "domain" for 53 with "udp"), or "unknown". The returned string may be
 * overwritten by the next call, so use it right away. Not thread-safe: call
 * only from one thread.
 */
const char *lookup_service_name(uint16_t port, const char *protocol);

/* Close the services database opened by lookup_service_name(). */
void close_service_database(void);

#endif /* JANUS_SERVICES_H */
