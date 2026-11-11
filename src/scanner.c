#include "scanner.h"

#include <errno.h>      /* errno, ECONNREFUSED */
#include <netdb.h>      /* getaddrinfo, freeaddrinfo, gai_strerror */
#include <stdio.h>      /* snprintf, fprintf */
#include <string.h>     /* memset, strerror */
#include <sys/socket.h> /* socket, connect */
#include <unistd.h>     /* close */

port_state scan_port(const char *host, int port)
{
    /*
     * getaddrinfo expects the port as text ("8000"), not as a number.
     * 16 bytes is more than enough for any int, including the sign
     * and the terminating '\0', so snprintf can never cut it off.
     */
    char port_text[16];
    snprintf(port_text, sizeof port_text, "%d", port);

    /* hints tells getaddrinfo what kind of address we want back. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); /* start with every field zeroed */
    hints.ai_family = AF_INET;       /* IPv4 only for now */
    hints.ai_socktype = SOCK_STREAM; /* stream socket = TCP */

    /* Turn "localhost" or "127.0.0.1" into a binary socket address. */
    struct addrinfo *address = NULL;
    int lookup_result = getaddrinfo(host, port_text, &hints, &address);
    if (lookup_result != 0) {
        fprintf(stderr, "janus: cannot resolve '%s': %s\n",
                host, gai_strerror(lookup_result));
        return PORT_ERROR;
    }

    /* Ask the kernel for a new TCP socket. We get back a small integer (fd). */
    int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd == -1) {
        perror("janus: socket");
        freeaddrinfo(address); /* do not leak the lookup result on error */
        return PORT_ERROR;
    }

    /*
     * connect() makes the kernel send a SYN and waits for the answer.
     * Read errno right away: any later library call may overwrite it.
     */
    port_state state;
    if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
        state = PORT_OPEN;
    } else if (errno == ECONNREFUSED) {
        state = PORT_CLOSED;
    } else {
        fprintf(stderr, "janus: connect to %s:%d failed: %s\n",
                host, port, strerror(errno));
        state = PORT_ERROR;
    }

    /* Always release both resources, whatever the result was. */
    close(fd);
    freeaddrinfo(address);
    return state;
}

const char *port_state_to_string(port_state state)
{
    switch (state) {
    case PORT_OPEN:
        return "open";
    case PORT_CLOSED:
        return "closed";
    case PORT_ERROR:
        return "error";
    }
    return "unknown"; /* unreachable, but keeps the compiler happy */
}
