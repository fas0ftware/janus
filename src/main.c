/*
 * Janus - a simple TCP connect port scanner for Linux.
 *
 * Authorized use only: scan only hosts and networks you own
 * or have explicit permission to test.
 */

#include <stdio.h>  /* printf, fprintf */
#include <stdlib.h> /* EXIT_SUCCESS, EXIT_FAILURE, strtol */
#include <string.h> /* strerror */

#include "scanner.h"

int main(int argc, char *argv[])
{
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <host> <port> [timeout_ms]\n", argv[0]);
        return EXIT_FAILURE;
    }

    /* Temporary, minimal parsing. Milestone 3 replaces this. */
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "janus: invalid port '%s' (expected 1-65535)\n", argv[2]);
        return EXIT_FAILURE;
    }

    long timeout_ms = 1000;
    if (argc == 4) {
        timeout_ms = strtol(argv[3], &end, 10);
        if (end == argv[3] || *end != '\0' || timeout_ms < 1 || timeout_ms > 60000) {
            fprintf(stderr, "janus: invalid timeout '%s' (expected 1-60000)\n", argv[3]);
            return EXIT_FAILURE;
        }
    }

    scan_target target;
    if (resolve_target(argv[1], &target) != 0) {
        return EXIT_FAILURE;
    }

    port_result result = scan_port(&target, (uint16_t)port, (int)timeout_ms);
    printf("%s:%ld %s\n", target.ip_text, port, port_state_to_string(result.state));
    if (result.state == PORT_ERROR) {
        fprintf(stderr, "janus: %s\n", strerror(result.error_code));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
