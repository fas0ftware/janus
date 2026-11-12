#ifndef JANUS_DISCOVERY_H
#define JANUS_DISCOVERY_H

#include <stdbool.h> /* bool */
#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */

#include "scanner.h"

/* Ports probed by --discover when --discover-ports is not given. */
#define DEFAULT_DISCOVER_PORTS "22,80,443,445,8080"

/*
 * Find out which hosts are alive, without raw sockets or root.
 *
 * Every probe is a normal TCP connect. A host counts as UP as soon as one
 * probe port answers with SYN-ACK (open) or RST (closed): either way a
 * machine on the other end replied. Hosts that stay silent on every probe
 * port (or are unreachable) count as DOWN. A host that drops all packets on
 * the probe ports therefore looks down; widen --discover-ports if needed.
 *
 * targets[i] is only probed when eligible[i] is true (resolved hosts).
 * up[i] is set to true or false for every i. Probes run in parallel with
 * settings->thread_count workers, and a host that already answered is not
 * probed on its remaining ports. Returns 0, or -1 on a setup error.
 */
int discover_hosts(const scan_target *targets, const bool *eligible, size_t host_count,
                   const uint16_t *probe_ports, size_t probe_count, const scan_settings *settings,
                   bool *up);

#endif /* JANUS_DISCOVERY_H */
