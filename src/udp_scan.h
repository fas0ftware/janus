#ifndef JANUS_UDP_SCAN_H
#define JANUS_UDP_SCAN_H

#include <stddef.h> /* size_t */
#include <stdint.h> /* uint16_t */

#include "scanner.h"

/*
 * Copy the datagram Janus sends to a UDP port into buffer and return its
 * length. Most UDP services ignore an empty datagram, so DNS (53) and NTP
 * (123) get a minimal, harmless query that makes them answer; every other
 * port gets an empty datagram (length 0). Exposed for tests.
 */
size_t udp_probe_payload(uint16_t port, unsigned char *buffer, size_t buffer_size);

/*
 * Scan one UDP port without root. The socket is "connected" to the target, so
 * the kernel reports an ICMP "port unreachable" as ECONNREFUSED:
 *
 *   a datagram comes back            -> open
 *   ICMP port unreachable            -> closed
 *   ICMP host unreachable / admin    -> filtered
 *   total silence until the timeout  -> open|filtered (UDP cannot tell them apart)
 *
 * The probe is sent twice within the timeout, because UDP packets get lost.
 */
port_result scan_udp_port(const scan_target *target, uint16_t port, const scan_settings *settings);

#endif /* JANUS_UDP_SCAN_H */
