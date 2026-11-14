#ifndef JANUS_VERSION_SCAN_H
#define JANUS_VERSION_SCAN_H

/*
 * --sv over TCP: talk to an open port just enough to learn what it runs.
 *
 * Probes, in order, each on its own connection, until one reply is recognized:
 *
 *   1. the port's usual opening: wait for a greeting (SSH, FTP, SMTP, MySQL,
 *      VNC, ...), or send HEAD on HTTP ports, a TLS ClientHello on TLS ports,
 *      a PostgreSQL SSLRequest on 5432/5433
 *   2. a TLS ClientHello   (silent services are often TLS)
 *   3. HEAD / HTTP/1.0     (or plain HTTP on an unusual port)
 *
 * A service that greets in a protocol Janus does not know is left alone after
 * the greeting. Nothing beyond these fixed, harmless probes is ever sent: no
 * logins, no guessed credentials, no exploit payloads.
 */

#include <stddef.h> /* size_t */

#include "scanner.h"

/* Longest "HEAD / HTTP/1.0" request (IPv6 address in the Host header included). */
#define HTTP_REQUEST_MAX 128

/* How long to wait for one reply: the scan timeout, but at most 1.5 s. */
int service_wait_ms(int timeout_ms);

/*
 * Write "HEAD / HTTP/1.0\r\nHost: <ip>\r\n\r\n" into buffer. Some servers
 * (e.g. CUPS) refuse requests without a Host header. Returns the length, or 0
 * if the buffer is too small.
 */
size_t http_head_request(const scan_target *target, char *buffer, size_t buffer_size);

/*
 * Identify the service behind an open port. connected_fd is the socket the
 * port scan just opened; it is used for the first probe and closed. Fills
 * result->detected (heap, or NULL if nothing matched) and result->banner (the
 * first text line any probe received).
 */
void detect_tcp_service(const scan_target *target, int connected_fd, const scan_settings *settings,
                        port_result *result);

#endif /* JANUS_VERSION_SCAN_H */
