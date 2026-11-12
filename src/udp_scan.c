#include "udp_scan.h"

#include <arpa/inet.h>  /* htons */
#include <errno.h>      /* errno, ECONNREFUSED, ... */
#include <fcntl.h>      /* fcntl, O_NONBLOCK */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr_in6 */
#include <poll.h>       /* poll, struct pollfd */
#include <string.h>     /* memset, memcpy */
#include <sys/socket.h> /* socket, connect, send, recv */
#include <unistd.h>     /* close */

#include "utils.h"

/* Longest single poll() wait, so a stop request is noticed quickly. */
#define POLL_SLICE_MS 100
/* How often the probe is sent within one timeout (UDP has no retransmission). */
#define UDP_ATTEMPTS 2
#define NTP_PACKET_SIZE 48

size_t udp_probe_payload(uint16_t port, unsigned char *buffer, size_t buffer_size)
{
    /* DNS: ID 0x1234, "recursion desired", one question: "." type NS, class IN. */
    static const unsigned char dns_query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01};
    switch (port) {
    case 53:
        if (buffer_size < sizeof dns_query) {
            return 0;
        }
        memcpy(buffer, dns_query, sizeof dns_query);
        return sizeof dns_query;
    case 123:
        /* NTP: first byte 0x1b = leap 0, version 3, mode 3 (client); the rest is zero. */
        if (buffer_size < NTP_PACKET_SIZE) {
            return 0;
        }
        memset(buffer, 0, NTP_PACKET_SIZE);
        buffer[0] = 0x1b;
        return NTP_PACKET_SIZE;
    default:
        return 0; /* an empty datagram is enough to trigger an ICMP error on a closed port */
    }
}

/* Map an error from connect(), send() or recv() on a UDP socket to a port state. */
static port_state classify_udp_error(int error_code)
{
    switch (error_code) {
    case ECONNREFUSED: /* ICMP port unreachable */
        return PORT_CLOSED;
    case EHOSTUNREACH: /* ICMP host unreachable */
    case EACCES:       /* ICMP "administratively prohibited": a firewall said no */
        return PORT_FILTERED;
    default:
        return PORT_ERROR;
    }
}

static port_result finish(port_result result, port_state state, int error_code)
{
    result.state = state;
    result.error_code = state == PORT_ERROR ? error_code : 0;
    return result;
}

port_result scan_udp_port(const scan_target *target, uint16_t port, const scan_settings *settings)
{
    port_result result = {.port = port, .state = PORT_NOT_SCANNED, .error_code = 0, .banner = ""};

    struct sockaddr_storage address = target->address;
    if (target->family == AF_INET) {
        ((struct sockaddr_in *)&address)->sin_port = htons(port);
    } else {
        ((struct sockaddr_in6 *)&address)->sin6_port = htons(port);
    }

    int fd = socket(target->family, SOCK_DGRAM, 0);
    if (fd == -1) {
        return finish(result, PORT_ERROR, errno);
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        int saved = errno;
        close(fd);
        return finish(result, PORT_ERROR, saved);
    }

    /*
     * connect() on a UDP socket sends nothing. It only fixes the peer, which
     * makes the kernel hand ICMP errors for this peer to us (as ECONNREFUSED
     * and friends) and drop datagrams from anyone else.
     */
    if (connect(fd, (const struct sockaddr *)&address, target->address_length) == -1) {
        int saved = errno;
        close(fd);
        return finish(result, classify_udp_error(saved), saved);
    }

    unsigned char payload[NTP_PACKET_SIZE];
    size_t payload_length = udp_probe_payload(port, payload, sizeof payload);

    int attempt_ms = settings->timeout_ms / UDP_ATTEMPTS;
    if (attempt_ms < 1) {
        attempt_ms = 1;
    }

    for (int attempt = 0; attempt < UDP_ATTEMPTS; attempt++) {
        if (send(fd, payload, payload_length, MSG_NOSIGNAL) == -1 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != ENOBUFS) {
            /* Typically ECONNREFUSED: an ICMP error from the previous attempt is still pending. */
            int saved = errno;
            close(fd);
            return finish(result, classify_udp_error(saved), saved);
        }

        struct pollfd watch = {.fd = fd, .events = POLLIN, .revents = 0};
        double deadline_ms = monotonic_time_ms() + attempt_ms;
        for (;;) {
            if (scan_stop_requested()) {
                close(fd);
                return result; /* PORT_NOT_SCANNED */
            }
            double remaining_ms = deadline_ms - monotonic_time_ms();
            if (remaining_ms <= 0) {
                break; /* silence for this attempt: send again, or give up */
            }
            int wait_ms = remaining_ms > POLL_SLICE_MS ? POLL_SLICE_MS : (int)remaining_ms + 1;

            int ready = poll(&watch, 1, wait_ms);
            if (ready == -1 && errno != EINTR) {
                int saved = errno;
                close(fd);
                return finish(result, PORT_ERROR, saved);
            }
            if (ready <= 0) {
                continue; /* slice over or a signal arrived */
            }

            /* Either a datagram arrived or an ICMP error is queued: recv() tells which. */
            unsigned char reply[512];
            if (recv(fd, reply, sizeof reply, 0) >= 0) {
                close(fd);
                return finish(result, PORT_OPEN, 0); /* any answer, even an empty one, means a listener */
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            int saved = errno;
            close(fd);
            return finish(result, classify_udp_error(saved), saved);
        }
    }

    close(fd);
    return finish(result, PORT_OPEN_FILTERED, 0);
}
