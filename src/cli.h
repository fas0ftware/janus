#ifndef JANUS_CLI_H
#define JANUS_CLI_H

#include <stdbool.h> /* bool */
#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */
#include <stdio.h>   /* FILE */

#define DEFAULT_PORTS "1-1024"
#define DEFAULT_TIMEOUT_MS 1000
#define MIN_TIMEOUT_MS 1
#define MAX_TIMEOUT_MS 60000
#define DEFAULT_THREAD_COUNT 16
#define MAX_THREAD_COUNT 256
#define MAX_TARGET_LENGTH 253 /* longest valid DNS name */

/* Everything the user asked for on the command line. */
typedef struct {
    const char *target; /* host, list "a,b" or CIDR; points into argv, not owned */
    uint16_t *ports;    /* sorted, no duplicates, heap allocated */
    size_t port_count;
    int timeout_ms;
    int thread_count;
    bool json_output;
    bool grab_banner; /* --banner */
    bool open_only;   /* --open: in multi-host scans, hide hosts without open ports */
    int family;       /* 0 = any, 4 = IPv4 only (-4), 6 = IPv6 only (-6) */
    bool udp;         /* -u / --udp: scan UDP instead of TCP */
    bool discover;    /* --discover: skip hosts that do not answer the probe ports */
    uint16_t *discover_ports; /* sorted, no duplicates, heap allocated; set when discover is true */
    size_t discover_port_count;
} scan_options;

typedef enum {
    PARSE_OK,           /* options are valid, go ahead and scan */
    PARSE_EXIT_SUCCESS, /* --help or --version was printed, exit with 0 */
    PARSE_ERROR         /* invalid input, an error message was printed */
} parse_status;

/* Fill *options from argv. On PARSE_OK, call free_options() later. */
parse_status parse_arguments(int argc, char *argv[], scan_options *options);

/* Release memory owned by *options. Safe to call more than once. */
void free_options(scan_options *options);

/*
 * Parse "80", "22,80,443", "1-1024" or a mix like "22,80-90".
 * On success *ports_out is a sorted, duplicate-free heap array. Returns 0 or -1.
 */
int parse_port_list(const char *text, uint16_t **ports_out, size_t *count_out);

void print_usage(FILE *stream, const char *program_name);

#endif /* JANUS_CLI_H */
