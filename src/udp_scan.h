#ifndef JANUS_UDP_SCAN_H
#define JANUS_UDP_SCAN_H

#include <stddef.h> /* size_t */
#include <stdint.h> /* uint16_t */

#include "scanner.h"

/*
 * Copy the datagram Janus sends to a UDP port into buffer and return its
 * length. Most UDP services ignore an empty datagram, so a few well-known
 * discovery services get their standard, harmless query: DNS (53), NTP (123),
 * NetBIOS name service (137), SSDP (1900) and mDNS (5353). Every other port
 * gets an empty datagram (length 0). Nothing is written if buffer_size is too
 * small. Exposed for tests.
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
