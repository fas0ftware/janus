#include "output.h"

#include <stdio.h>  /* printf, fprintf */
#include <string.h> /* strerror */

#include "services.h"
#include "utils.h"

/* How many ports ended up in each state. */
typedef struct {
    size_t open;
    size_t closed;
    size_t filtered;
    size_t error;
    size_t not_scanned;
    int first_error_code; /* to explain errors with one example */
} state_counts;

static state_counts count_states(const scan_report *report)
{
    state_counts counts = {0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < report->result_count; i++) {
        switch (report->results[i].state) {
        case PORT_OPEN:
            counts.open++;
            break;
        case PORT_CLOSED:
            counts.closed++;
            break;
        case PORT_FILTERED:
            counts.filtered++;
            break;
        case PORT_ERROR:
            if (counts.error == 0) {
                counts.first_error_code = report->results[i].error_code;
            }
            counts.error++;
            break;
        case PORT_NOT_SCANNED:
            counts.not_scanned++;
            break;
        }
    }
    return counts;
}

/* Problems go to stderr so they never mix with the result on stdout. */
static void print_warnings(const scan_report *report, const state_counts *counts)
{
    if (counts->error > 0) {
        print_error("%zu port(s) could not be checked, first error: %s",
                    counts->error, strerror(counts->first_error_code));
    }
    if (report->interrupted) {
        print_error("scan interrupted, %zu port(s) not scanned, results are partial",
                    counts->not_scanned);
    }
}

void print_result_text(const scan_report *report)
{
    state_counts counts = count_states(report);

    printf("Janus scan report for %s (%s)\n", report->target, report->ip_address);
    printf("Started: %s\n\n", report->started_at);

    if (counts.open == 0) {
        printf("No open ports found.\n");
    } else {
        /* %-10s pads to 10 columns, left aligned, so columns line up. */
        printf("%-10s %-8s %s\n", "PORT", "STATE", "SERVICE");
        for (size_t i = 0; i < report->result_count; i++) {
            const port_result *result = &report->results[i];
            if (result->state != PORT_OPEN) {
                continue;
            }
            char port_label[16];
            snprintf(port_label, sizeof port_label, "%u/tcp", (unsigned)result->port);
            printf("%-10s %-8s %s\n", port_label, port_state_to_string(result->state),
                   lookup_service_name(result->port));
        }
    }

    printf("\nScanned %zu port(s) in %.2f s: %zu open, %zu closed, %zu filtered",
           report->result_count, report->duration_ms / 1000.0,
           counts.open, counts.closed, counts.filtered);
    if (counts.error > 0) {
        printf(", %zu error", counts.error);
    }
    if (counts.not_scanned > 0) {
        printf(", %zu not scanned", counts.not_scanned);
    }
    printf("\n");

    print_warnings(report, &counts);
}
