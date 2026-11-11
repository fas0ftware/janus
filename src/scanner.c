#include "scanner.h"

#include <arpa/inet.h>  /* inet_ntop, htons */
#include <errno.h>      /* errno, EINPROGRESS, ECONNREFUSED, ... */
#include <fcntl.h>      /* fcntl, O_NONBLOCK */
#include <netdb.h>      /* getaddrinfo, freeaddrinfo, gai_strerror */
#include <poll.h>       /* poll, struct pollfd */
#include <string.h>     /* memset, memcpy */
#include <sys/socket.h> /* socket, connect, getsockopt */
#include <unistd.h>     /* close */

#include "utils.h"

int resolve_target(const char *host, scan_target *target)
{
    /* hints tells getaddrinfo what kind of address we want back. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); /* start with every field zeroed */
    hints.ai_family = AF_INET;       /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM; /* stream socket = TCP */

    struct addrinfo *results = NULL;
    int lookup_result = getaddrinfo(host, NULL, &hints, &results);
    if (lookup_result != 0) {
        print_error("cannot resolve '%s': %s", host, gai_strerror(lookup_result));
        return -1;
    }

    /* Keep only the first address; copy it so we can free the list right away. */
    memset(target, 0, sizeof *target);
    memcpy(&target->address, results->ai_addr, sizeof target->address);
    freeaddrinfo(results);

    /* Binary address -> "127.0.0.1" for display. */
    if (inet_ntop(AF_INET, &target->address.sin_addr,
                  target->ip_text, sizeof target->ip_text) == NULL) {
        print_error("cannot format address of '%s'", host);
        return -1;
    }
    return 0;
}

/* Put the socket into non-blocking mode so connect() returns immediately. */
static int set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0); /* read the current flags first ... */
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK); /* ... then add one flag */
}

/* Map a connect error (errno or SO_ERROR value) to a port state. */
static port_state classify_connect_error(int error_code)
{
    switch (error_code) {
    case 0:
        return PORT_OPEN;
    case ECONNREFUSED: /* RST received */
        return PORT_CLOSED;
    case ETIMEDOUT:    /* kernel gave up waiting */
    case EHOSTUNREACH: /* ICMP "host unreachable", often sent by firewalls */
        return PORT_FILTERED;
    default:
        return PORT_ERROR;
    }
}

/*
 * Start a TCP handshake and wait at most timeout_ms for it to finish.
 * On PORT_ERROR the errno value is stored in *error_code.
 */
static port_state connect_with_timeout(const struct sockaddr_in *address,
                                       int timeout_ms, int *error_code)
{
    *error_code = 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        *error_code = errno;
        return PORT_ERROR;
    }

    if (set_non_blocking(fd) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }

    /*
     * Non-blocking connect: the kernel sends the SYN and returns at once.
     * EINPROGRESS means "handshake started, result comes later".
     */
    if (connect(fd, (const struct sockaddr *)address, sizeof *address) == 0) {
        close(fd); /* connected instantly (can happen on localhost) */
        return PORT_OPEN;
    }
    if (errno != EINPROGRESS) {
        port_state state = classify_connect_error(errno);
        if (state == PORT_ERROR) {
            *error_code = errno;
        }
        close(fd);
        return state;
    }

    /*
     * Wait until the socket becomes writable (handshake finished, either
     * way) or until the timeout expires. poll returns 0 on timeout.
     */
    struct pollfd watch = {.fd = fd, .events = POLLOUT, .revents = 0};
    int ready = poll(&watch, 1, timeout_ms);
    if (ready == 0) {
        close(fd);
        return PORT_FILTERED; /* silence: no SYN-ACK and no RST */
    }
    if (ready == -1) {
        *error_code = errno; /* includes EINTR when Ctrl+C interrupts poll */
        close(fd);
        return PORT_ERROR;
    }

    /* The socket is "ready", but did the handshake succeed? Ask the kernel. */
    int socket_error = 0;
    socklen_t length = sizeof socket_error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }
    close(fd);

    port_state state = classify_connect_error(socket_error);
    if (state == PORT_ERROR) {
        *error_code = socket_error;
    }
    return state;
}

port_result scan_port(const scan_target *target, uint16_t port, int timeout_ms)
{
    /* Copy the resolved address and fill in the port for this attempt. */
    struct sockaddr_in address = target->address;
    address.sin_port = htons(port); /* host byte order -> network byte order */

    port_result result = {.port = port, .state = PORT_NOT_SCANNED, .error_code = 0};
    result.state = connect_with_timeout(&address, timeout_ms, &result.error_code);
    return result;
}

int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    int timeout_ms, int thread_count)
{
    (void)thread_count; /* sequential for now; Milestone 6 adds threads */
    for (size_t i = 0; i < count; i++) {
        results[i] = scan_port(target, results[i].port, timeout_ms);
    }
    return 0;
}

const char *port_state_to_string(port_state state)
{
    switch (state) {
    case PORT_NOT_SCANNED:
        return "not-scanned";
    case PORT_OPEN:
        return "open";
    case PORT_CLOSED:
        return "closed";
    case PORT_FILTERED:
        return "filtered";
    case PORT_ERROR:
        return "error";
    }
    return "unknown"; /* unreachable, but keeps the compiler happy */
}
