#include "output.h"

#include <stdbool.h> /* bool */
#include <stdio.h>   /* printf, putchar, fputs */
#include <string.h>  /* strcmp, strerror */

#include "fingerprint.h"
#include "services.h"
#include "utils.h"

/* How many ports ended up in each state. */
typedef struct {
    size_t open;
    size_t open_filtered; /* UDP only */
    size_t closed;
    size_t filtered;
    size_t error;
    size_t not_scanned;
    int first_error_code; /* to explain errors with one example */
} state_counts;

static state_counts count_states(const scan_report *report)
{
    state_counts counts = {0, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < report->result_count; i++) {
        switch (report->results[i].state) {
        case PORT_OPEN:
            counts.open++;
            break;
        case PORT_OPEN_FILTERED:
            counts.open_filtered++;
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

static size_t count_in_state(const scan_report *report, port_state state)
{
    size_t total = 0;
    for (size_t i = 0; i < report->result_count; i++) {
        total += report->results[i].state == state;
    }
    return total;
}

size_t count_open(const scan_report *report)
{
    return count_in_state(report, PORT_OPEN);
}

size_t count_open_filtered(const scan_report *report)
{
    return count_in_state(report, PORT_OPEN_FILTERED);
}

static const char *protocol_name(const scan_report *report)
{
    return report->protocol == PROTOCOL_UDP ? "udp" : "tcp";
}

/*
 * The SERVICE column: what --sv found if it found something, otherwise the
 * name /etc/services gives the port number. TLS is shown together with the
 * port's usual service, "tls/https", because --sv cannot look inside it.
 */
static const char *service_label(const port_result *result, const char *protocol, char *buffer, size_t size)
{
    const char *by_port = lookup_service_name(result->port, protocol);
    if (result->detected == NULL || result->detected->service[0] == '\0') {
        return by_port;
    }
    if (strcmp(result->detected->service, "tls") == 0 && strcmp(by_port, "unknown") != 0) {
        snprintf(buffer, size, "tls/%.*s", (int)(size > 5 ? size - 5 : 0), by_port);
        return buffer;
    }
    return result->detected->service;
}

/*
 * Two lines under a TLS port: who the certificate is for and until when, then
 * the names it is valid for. Problems are written in capitals so they stand out.
 */
static void print_certificate_text(const tls_certificate *certificate, const char *now)
{
    printf("%-10s cert: %s", "", certificate->subject[0] ? certificate->subject : "(no name)");
    if (certificate->self_signed) {
        printf(", self-signed");
    } else if (certificate->issuer[0] != '\0') {
        printf(", issuer %s", certificate->issuer);
    }
    printf(", valid until %.10s", certificate->not_after);
    if (certificate->key[0] != '\0') {
        printf(", %s", certificate->key);
    }
    if (certificate_expired(certificate, now)) {
        printf(", EXPIRED");
    } else if (certificate_not_yet_valid(certificate, now)) {
        printf(", NOT YET VALID");
    }
    printf("\n");
    if (certificate->name_count > 0) {
        printf("%-10s names: ", "");
        for (size_t i = 0; i < certificate->name_count; i++) {
            printf("%s%s", i ? ", " : "", certificate->names[i]);
        }
        printf("\n");
    }
}

/* PORT, STATE, SERVICE and VERSION; certificate and banner go on their own lines below. */
static void print_version_table(const scan_report *report, int state_width)
{
    const char *protocol = protocol_name(report);
    printf("%-10s %-*s %-16s %s\n", "PORT", state_width, "STATE", "SERVICE", "VERSION");
    for (size_t i = 0; i < report->result_count; i++) {
        const port_result *result = &report->results[i];
        if (result->state != PORT_OPEN && result->state != PORT_OPEN_FILTERED) {
            continue;
        }
        char port_label[16];
        char service_buffer[40];
        char version[DETECTED_PRODUCT_SIZE + DETECTED_VERSION_SIZE + DETECTED_INFO_SIZE + 8] = "";
        snprintf(port_label, sizeof port_label, "%u/%s", (unsigned)result->port, protocol);
        if (result->detected != NULL) {
            format_detected_version(result->detected, version, sizeof version);
        }
        printf("%-10s %-*s %-16s %s\n", port_label, state_width, port_state_to_string(result->state),
               service_label(result, protocol, service_buffer, sizeof service_buffer), version[0] ? version : "-");
        if (result->detected != NULL && result->detected->starttls_status == STARTTLS_OK) {
            printf("%-10s starttls: %s\n", "", result->detected->starttls);
        } else if (result->detected != NULL && result->detected->starttls_status == STARTTLS_NOT_OFFERED) {
            printf("%-10s starttls: NOT OFFERED (logins travel in clear text)\n", "");
        }
        if (result->detected != NULL && result->detected->certificate.present) {
            print_certificate_text(&result->detected->certificate, report->started_at);
        }
        if (report->show_banner && result->banner[0] != '\0') {
            printf("%-10s banner: %s\n", "", result->banner);
        }
    }
}

/*
 * Table of open ports (and, for UDP, open|filtered ones); adds a BANNER column
 * when --banner was given. The UDP state "open|filtered" needs a wider column.
 */
static void print_open_table(const scan_report *report)
{
    const char *protocol = protocol_name(report);
    int state_width = report->protocol == PROTOCOL_UDP ? 14 : 8;

    if (report->show_version) {
        print_version_table(report, state_width);
        return;
    }
    /* %-10s pads to 10 columns, left aligned, so columns line up. */
    if (report->show_banner) {
        printf("%-10s %-*s %-16s %s\n", "PORT", state_width, "STATE", "SERVICE", "BANNER");
    } else {
        printf("%-10s %-*s %s\n", "PORT", state_width, "STATE", "SERVICE");
    }
    for (size_t i = 0; i < report->result_count; i++) {
        const port_result *result = &report->results[i];
        if (result->state != PORT_OPEN && result->state != PORT_OPEN_FILTERED) {
            continue;
        }
        char port_label[16];
        snprintf(port_label, sizeof port_label, "%u/%s", (unsigned)result->port, protocol);
        const char *state_text = port_state_to_string(result->state);
        if (report->show_banner) {
            printf("%-10s %-*s %-16s %s\n", port_label, state_width, state_text,
                   lookup_service_name(result->port, protocol), result->banner[0] ? result->banner : "-");
        } else {
            printf("%-10s %-*s %s\n", port_label, state_width, state_text,
                   lookup_service_name(result->port, protocol));
        }
    }
}

void print_result_text(const scan_report *report)
{
    state_counts counts = count_states(report);

    printf("Janus scan report for %s (%s)\n", report->target, report->ip_address);
    printf("Started: %s\n\n", report->started_at);

    if (report->status == HOST_DOWN) {
        /* No port scan was done, so there is no port summary to print. */
        printf("Host seems down: no answer on the discovery ports. "
               "Run without --discover to scan it anyway.\n");
        return;
    }
    if (counts.open + counts.open_filtered == 0) {
        printf("No open ports found.\n");
    } else {
        print_open_table(report);
    }

    printf("\nScanned %zu port(s) in %.2f s: %zu open, ", report->result_count - counts.not_scanned,
           report->duration_ms / 1000.0, counts.open);
    if (report->protocol == PROTOCOL_UDP) {
        printf("%zu open|filtered, ", counts.open_filtered);
    }
    printf("%zu closed, %zu filtered", counts.closed, counts.filtered);
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

/* --sv result of one port: an object with four strings ("" = unknown), or null if nothing was recognized. */
static void print_certificate_json(const tls_certificate *certificate, const char *now)
{
    printf(", \"certificate\": ");
    if (!certificate->present) {
        printf("null");
        return;
    }
    printf("{\"subject\": ");
    print_json_string(certificate->subject);
    printf(", \"issuer\": ");
    print_json_string(certificate->issuer);
    printf(", \"self_signed\": %s, \"not_before\": ", certificate->self_signed ? "true" : "false");
    print_json_string(certificate->not_before);
    printf(", \"not_after\": ");
    print_json_string(certificate->not_after);
    printf(", \"expired\": %s, \"not_yet_valid\": %s, \"key\": ",
           certificate_expired(certificate, now) ? "true" : "false",
           certificate_not_yet_valid(certificate, now) ? "true" : "false");
    print_json_string(certificate->key);
    printf(", \"names\": [");
    for (size_t i = 0; i < certificate->name_count; i++) {
        printf("%s", i ? ", " : "");
        print_json_string(certificate->names[i]);
    }
    printf("]}");
}

static void print_detected_json(const service_info *detected, const char *now)
{
    printf(", \"detected\": ");
    if (detected == NULL) {
        printf("null");
        return;
    }
    printf("{\"service\": ");
    print_json_string(detected->service);
    printf(", \"product\": ");
    print_json_string(detected->product);
    printf(", \"version\": ");
    print_json_string(detected->version);
    printf(", \"info\": ");
    print_json_string(detected->info);
    printf(", \"starttls\": ");
    if (detected->starttls_status == STARTTLS_NOT_APPLICABLE) {
        printf("null");
    } else if (detected->starttls_status == STARTTLS_NOT_OFFERED) {
        printf("{\"offered\": false}");
    } else {
        printf("{\"offered\": true, \"tls\": ");
        print_json_string(detected->starttls);
        printf("}");
    }
    print_certificate_json(&detected->certificate, now);
    printf("}");
}

/* One JSON array of the ports in a given state, e.g. "open_ports": [ {...}, {...} ], with a trailing comma. */
static void print_port_array(const scan_report *report, const char *pad, const char *key, port_state wanted)
{
    const char *protocol = protocol_name(report);
    printf("%s\"%s\": [", pad, key);
    bool first = true;
    for (size_t i = 0; i < report->result_count; i++) {
        const port_result *result = &report->results[i];
        if (result->state != wanted) {
            continue;
        }
        /* JSON does not allow a trailing comma, so print it before each item but the first. */
        printf("%s\n%s  {\"port\": %u, \"protocol\": \"%s\", \"service\": ", first ? "" : ",", pad,
               (unsigned)result->port, protocol);
        print_json_string(lookup_service_name(result->port, protocol));
        if (wanted == PORT_OPEN && report->show_banner) {
            printf(", \"banner\": ");
            print_json_string(result->banner);
        }
        if (wanted == PORT_OPEN && report->show_version) {
            print_detected_json(result->detected, report->started_at);
        }
        printf("}");
        first = false;
    }
    if (first) {
        printf("],\n");
    } else {
        printf("\n%s],\n", pad);
    }
}

/* The per-host keys, shared by the single-host and multi-host documents. */
static void print_host_fields(const scan_report *report, const char *pad, const state_counts *counts)
{
    printf("%s\"target\": ", pad);
    print_json_string(report->target);
    printf(",\n%s\"ip\": ", pad);
    print_json_string(report->ip_address);
    printf(",\n%s\"protocol\": \"%s\",\n", pad, protocol_name(report));
    printf("%s\"resolved\": %s,\n", pad, report->resolved ? "true" : "false");
    if (report->status != HOST_STATUS_UNKNOWN) {
        printf("%s\"status\": \"%s\",\n", pad, report->status == HOST_UP ? "up" : "down");
    }
    /* Whole milliseconds: integers are simpler for other programs to read. */
    printf("%s\"duration_ms\": %.0f,\n", pad, report->duration_ms);
    printf("%s\"ports_requested\": %zu,\n", pad, report->result_count);
    printf("%s\"ports_scanned\": %zu,\n", pad, report->result_count - counts->not_scanned);
    printf("%s\"interrupted\": %s,\n", pad, report->interrupted ? "true" : "false");

    print_port_array(report, pad, "open_ports", PORT_OPEN);
    if (report->protocol == PROTOCOL_UDP) {
        print_port_array(report, pad, "open_filtered_ports", PORT_OPEN_FILTERED);
    }

    printf("%s\"summary\": {\"open\": %zu, ", pad, counts->open);
    if (report->protocol == PROTOCOL_UDP) {
        printf("\"open_filtered\": %zu, ", counts->open_filtered);
    }
    printf("\"closed\": %zu, \"filtered\": %zu, \"error\": %zu, \"not_scanned\": %zu}", counts->closed,
           counts->filtered, counts->error, counts->not_scanned);
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

void print_multi_text(const scan_report *reports, size_t count, bool open_only, bool discovery,
                      double duration_ms)
{
    size_t with_open = 0, unresolved = 0, shown = 0, up = 0, down = 0;
    for (size_t h = 0; h < count; h++) {
        const scan_report *report = &reports[h];
        size_t open = report->resolved ? count_open(report) : 0;
        size_t uncertain = report->resolved ? count_open_filtered(report) : 0; /* UDP: silent ports */
        with_open += open > 0;
        unresolved += !report->resolved;
        up += report->status == HOST_UP;
        down += report->status == HOST_DOWN;
        if (report->status == HOST_DOWN) {
            continue; /* hosts that are down are counted in the summary, not listed */
        }
        if (open_only && open == 0 && uncertain == 0) {
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
        if (open == 0 && uncertain == 0) {
            printf("no open ports\n");
        } else {
            printf("%zu open", open);
            if (uncertain > 0) {
                printf(", %zu open|filtered", uncertain);
            }
            printf("\n");
            print_open_table(report);
        }
    }
    printf("%sScanned %zu host(s) in %.2f s: ", shown ? "\n" : "", count, duration_ms / 1000.0);
    if (discovery) {
        printf("%zu up, %zu down, ", up, down);
    }
    printf("%zu with open ports", with_open);
    if (unresolved > 0) {
        printf(", %zu unresolved", unresolved);
    }
    printf("\n");
}

void print_multi_json(const scan_report *reports, size_t count, const char *spec,
                      const char *started_at, bool discovery, double duration_ms)
{
    size_t with_open = 0, up = 0, down = 0;
    printf("{\n  \"scanner\": \"janus\",\n  \"version\": \"%s\",\n  \"spec\": ", JANUS_VERSION);
    print_json_string(spec);
    printf(",\n  \"timestamp\": ");
    print_json_string(started_at);
    printf(",\n  \"duration_ms\": %.0f,\n  \"hosts\": [", duration_ms);
    for (size_t h = 0; h < count; h++) {
        state_counts counts = count_states(&reports[h]);
        with_open += reports[h].resolved && counts.open > 0;
        up += reports[h].status == HOST_UP;
        down += reports[h].status == HOST_DOWN;
        printf("%s\n    {\n", h ? "," : "");
        print_host_fields(&reports[h], "      ", &counts);
        printf("\n    }");
    }
    printf("%s],\n  \"summary\": {\"hosts\": %zu, \"hosts_with_open_ports\": %zu", count ? "\n  " : "", count,
           with_open);
    if (discovery) {
        printf(", \"hosts_up\": %zu, \"hosts_down\": %zu", up, down);
    }
    printf("}\n}\n");
}
