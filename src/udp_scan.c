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

/* Largest probe datagram; the buffer in scan_udp_port() has this size. */
#define UDP_PAYLOAD_MAX 128

/* DNS: ID 0x1234, "recursion desired", one question: "." type NS, class IN. */
static const unsigned char dns_query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01};

/*
 * mDNS (legacy unicast query, RFC 6762 section 6.7): one question,
 * "_services._dns-sd._udp.local" type PTR class IN. Responders answer with the
 * list of service types they offer (printers, Chromecasts, AirPlay, ...).
 */
static const unsigned char mdns_query[] = {
    0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* header */
    9,    '_',  's',  'e',  'r',  'v',  'i',  'c',  'e',  's',
    7,    '_',  'd',  'n',  's',  '-',  's',  'd',
    4,    '_',  'u',  'd',  'p',
    5,    'l',  'o',  'c',  'a',  'l',  0x00,
    0x00, 0x0c, 0x00, 0x01, /* type PTR, class IN */
};

/* SSDP / UPnP discovery request, the same one routers and media servers expect. */
static const char ssdp_search[] = "M-SEARCH * HTTP/1.1\r\n"
                                  "HOST: 239.255.255.250:1900\r\n"
                                  "MAN: \"ssdp:discover\"\r\n"
                                  "MX: 1\r\n"
                                  "ST: ssdp:all\r\n"
                                  "\r\n";

/*
 * NetBIOS name service "node status" request (NBSTAT) for the wildcard name "*".
 * The name is half-ASCII encoded: '*' followed by 15 NUL bytes becomes "CK" + 30 times 'A'.
 */
static const unsigned char netbios_status[] = {
    0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* header */
    0x20,                                                                   /* name length: 32 */
    'C',  'K', /* encoded '*' */
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
    0x00,                   /* end of name */
    0x00, 0x21, 0x00, 0x01, /* type NBSTAT, class IN */
};

/* Copy a fixed probe into buffer, or write nothing (and return 0) if it does not fit. */
static size_t copy_probe(const void *probe, size_t probe_length, unsigned char *buffer, size_t buffer_size)
{
    if (buffer_size < probe_length) {
        return 0;
    }
    memcpy(buffer, probe, probe_length);
    return probe_length;
}

size_t udp_probe_payload(uint16_t port, unsigned char *buffer, size_t buffer_size)
{
    switch (port) {
    case 53:
        return copy_probe(dns_query, sizeof dns_query, buffer, buffer_size);
    case 123:
        /* NTP: first byte 0x1b = leap 0, version 3, mode 3 (client); the rest is zero. */
        if (buffer_size < NTP_PACKET_SIZE) {
            return 0;
        }
        memset(buffer, 0, NTP_PACKET_SIZE);
        buffer[0] = 0x1b;
        return NTP_PACKET_SIZE;
    case 137:
        return copy_probe(netbios_status, sizeof netbios_status, buffer, buffer_size);
    case 1900:
        return copy_probe(ssdp_search, sizeof ssdp_search - 1, buffer, buffer_size); /* without the NUL */
    case 5353:
        return copy_probe(mdns_query, sizeof mdns_query, buffer, buffer_size);
    default:
        /*
         * An empty datagram is enough to make a closed port answer with ICMP. Other services
         * (SNMP needs a community string, for example) are deliberately not probed: Janus
         * sends no guessed credentials.
         */
        return 0;
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

    unsigned char payload[UDP_PAYLOAD_MAX];
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
