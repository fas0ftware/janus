#ifndef JANUS_OUTPUT_H
#define JANUS_OUTPUT_H

#include <stdbool.h> /* bool */
#include <stddef.h>  /* size_t */

#include "scanner.h"

#define TIMESTAMP_SIZE 32

/* Everything needed to print the result of one scan. */
typedef struct {
    const char *target;         /* as typed by the user */
    const char *ip_address;     /* resolved IPv4 address */
    const port_result *results; /* one entry per requested port, sorted */
    size_t result_count;
    char started_at[TIMESTAMP_SIZE]; /* UTC, ISO 8601 */
    double duration_ms;
    bool interrupted; /* true if the user pressed Ctrl+C */
    bool show_banner; /* --banner was given */
    bool show_version; /* --sv was given: VERSION column and "detected" in JSON */
    bool resolved;    /* false if the host could not be resolved (multi-host runs) */
    host_status status; /* result of --discover; HOST_STATUS_UNKNOWN if it was not used */
    scan_protocol protocol; /* tcp or udp: decides labels, the state column and JSON keys */
} scan_report;

/* Human-readable table of open ports plus a summary line. */
void print_result_text(const scan_report *report);

/*
 * Machine-readable JSON (open ports only, plus metadata and counts),
 * meant to be read by other programs such as network-monitor.
 */
void print_result_json(const scan_report *report);

/*
 * Several hosts: one compact block per host in text, one JSON document with a "hosts" array.
 * discovery is true when --discover ran: hosts that are down are then counted in the
 * summary (text) or marked "down" (JSON) instead of being listed as scanned.
 */
void print_multi_text(const scan_report *reports, size_t count, bool open_only, bool discovery,
                      double duration_ms);
void print_multi_json(const scan_report *reports, size_t count, const char *spec,
                      const char *started_at, bool discovery, double duration_ms);

/* Number of open ports in a report. */
size_t count_open(const scan_report *report);

/* Number of UDP ports that stayed silent (open|filtered); always 0 for TCP. */
size_t count_open_filtered(const scan_report *report);

#endif /* JANUS_OUTPUT_H */
