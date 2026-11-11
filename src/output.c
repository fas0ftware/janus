#include "output.h"

#include <stdbool.h> /* bool */
#include <stdio.h>   /* printf, putchar, fputs */
#include <string.h>  /* strcmp, strerror */

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

size_t count_open(const scan_report *report)
{
    size_t open = 0;
    for (size_t i = 0; i < report->result_count; i++) {
        open += report->results[i].state == PORT_OPEN;
    }
    return open;
}

/* Table of open ports; adds a BANNER column when --banner was given. */
static void print_open_table(const scan_report *report)
{
    /* %-10s pads to 10 columns, left aligned, so columns line up. */
    if (report->show_banner) {
        printf("%-10s %-8s %-16s %s\n", "PORT", "STATE", "SERVICE", "BANNER");
    } else {
        printf("%-10s %-8s %s\n", "PORT", "STATE", "SERVICE");
    }
    for (size_t i = 0; i < report->result_count; i++) {
        const port_result *result = &report->results[i];
        if (result->state != PORT_OPEN) {
            continue;
        }
        char port_label[16];
        snprintf(port_label, sizeof port_label, "%u/tcp", (unsigned)result->port);
        if (report->show_banner) {
            printf("%-10s %-8s %-16s %s\n", port_label, port_state_to_string(result->state),
                   lookup_service_name(result->port), result->banner[0] ? result->banner : "-");
        } else {
            printf("%-10s %-8s %s\n", port_label, port_state_to_string(result->state),
                   lookup_service_name(result->port));
        }
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
        print_open_table(report);
    }

    printf("\nScanned %zu port(s) in %.2f s: %zu open, %zu closed, %zu filtered",
           report->result_count - counts.not_scanned, report->duration_ms / 1000.0,
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

/*
 * Print a string as a JSON string literal, including the quotes.
 * JSON forbids raw control characters inside strings and gives '"' and
 * '\\' a special meaning, so those must be escaped. Bytes >= 0x80 are
 * copied unchanged (they are part of UTF-8 characters).
 */
static void print_json_string(const char *text)
{
    putchar('"');
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; cursor++) {
        unsigned char c = *cursor;
        switch (c) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        default:
            if (c < 0x20) {
                printf("\\u%04x", (unsigned)c); /* other control characters */
            } else {
                putchar(c);
            }
        }
    }
    putchar('"');
}

/* The per-host keys, shared by the single-host and multi-host documents. */
static void print_host_fields(const scan_report *report, const char *pad, const state_counts *counts)
{
    printf("%s\"target\": ", pad);
    print_json_string(report->target);
    printf(",\n%s\"ip\": ", pad);
    print_json_string(report->ip_address);
    printf(",\n%s\"resolved\": %s,\n", pad, report->resolved ? "true" : "false");
    /* Whole milliseconds: integers are simpler for other programs to read. */
    printf("%s\"duration_ms\": %.0f,\n", pad, report->duration_ms);
    printf("%s\"ports_requested\": %zu,\n", pad, report->result_count);
    printf("%s\"ports_scanned\": %zu,\n", pad, report->result_count - counts->not_scanned);
    printf("%s\"interrupted\": %s,\n", pad, report->interrupted ? "true" : "false");

    printf("%s\"open_ports\": [", pad);
    bool first = true;
    for (size_t i = 0; i < report->result_count; i++) {
        const port_result *result = &report->results[i];
        if (result->state != PORT_OPEN) {
            continue;
        }
        /* JSON does not allow a trailing comma, so print it before each item but the first. */
        printf("%s\n%s  {\"port\": %u, \"protocol\": \"tcp\", \"service\": ", first ? "" : ",", pad,
               (unsigned)result->port);
        print_json_string(lookup_service_name(result->port));
        if (report->show_banner) {
            printf(", \"banner\": ");
            print_json_string(result->banner);
        }
        printf("}");
        first = false;
    }
    if (first) {
        printf("],\n");
    } else {
        printf("\n%s],\n", pad);
    }

    printf("%s\"summary\": {\"open\": %zu, \"closed\": %zu, \"filtered\": %zu, "
           "\"error\": %zu, \"not_scanned\": %zu}",
           pad, counts->open, counts->closed, counts->filtered, counts->error, counts->not_scanned);
}

void print_result_json(const scan_report *report)
{
    state_counts counts = count_states(report);

    printf("{\n");
    printf("  \"scanner\": \"janus\",\n");
    printf("  \"version\": \"%s\",\n", JANUS_VERSION);
    printf("  \"timestamp\": ");
    print_json_string(report->started_at);
    printf(",\n");
    print_host_fields(report, "  ", &counts);
    printf("\n}\n");

    print_warnings(report, &counts);
}

void print_multi_text(const scan_report *reports, size_t count, bool open_only, double duration_ms)
{
    size_t with_open = 0, unresolved = 0, shown = 0;
    for (size_t h = 0; h < count; h++) {
        const scan_report *report = &reports[h];
        size_t open = report->resolved ? count_open(report) : 0;
        with_open += open > 0;
        unresolved += !report->resolved;
        if (open_only && open == 0) {
            continue;
        }
        if (shown++ > 0) {
            printf("\n");
        }
        if (!report->resolved) {
            printf("%s: could not be resolved\n", report->target);
            continue;
        }
        if (strcmp(report->target, report->ip_address) == 0) {
            printf("%s: ", report->target);
        } else {
            printf("%s (%s): ", report->target, report->ip_address);
        }
        if (open == 0) {
            printf("no open ports\n");
        } else {
            printf("%zu open\n", open);
            print_open_table(report);
        }
    }
    printf("%sScanned %zu host(s) in %.2f s: %zu with open ports", shown ? "\n" : "", count,
           duration_ms / 1000.0, with_open);
    if (unresolved > 0) {
        printf(", %zu unresolved", unresolved);
    }
    printf("\n");
}

void print_multi_json(const scan_report *reports, size_t count, const char *spec,
                      const char *started_at, double duration_ms)
{
    size_t with_open = 0;
    printf("{\n  \"scanner\": \"janus\",\n  \"version\": \"%s\",\n  \"spec\": ", JANUS_VERSION);
    print_json_string(spec);
    printf(",\n  \"timestamp\": ");
    print_json_string(started_at);
    printf(",\n  \"duration_ms\": %.0f,\n  \"hosts\": [", duration_ms);
    for (size_t h = 0; h < count; h++) {
        state_counts counts = count_states(&reports[h]);
        with_open += reports[h].resolved && counts.open > 0;
        printf("%s\n    {\n", h ? "," : "");
        print_host_fields(&reports[h], "      ", &counts);
        printf("\n    }");
    }
    printf("%s],\n  \"summary\": {\"hosts\": %zu, \"hosts_with_open_ports\": %zu}\n}\n",
           count ? "\n  " : "", count, with_open);
}
