/*
 * Janus - a simple TCP connect port scanner for Linux.
 *
 * Authorized use only: scan only hosts and networks you own
 * or have explicit permission to test.
 */

#include <stdio.h>  /* printf, fprintf */
#include <stdlib.h> /* EXIT_SUCCESS, EXIT_FAILURE, strtol */

#include "scanner.h"

int main(int argc, char *argv[])
{
    /* argv[0] is the program name, so we expect exactly 2 more arguments. */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *host = argv[1];

    /*
     * Temporary, minimal port parsing. Milestone 3 replaces this with
     * proper option handling and validation.
     * strtol sets 'end' to the first character it could not parse,
     * so "80abc" leaves end pointing at "abc" and we reject it.
     */
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "janus: invalid port '%s' (expected 1-65535)\n", argv[2]);
        return EXIT_FAILURE;
    }

    port_state state = scan_port(host, (int)port);
    printf("%s:%ld %s\n", host, port, port_state_to_string(state));

    return state == PORT_ERROR ? EXIT_FAILURE : EXIT_SUCCESS;
}
