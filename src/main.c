/*
 * Janus - a simple TCP connect port scanner for Linux.
 *
 * Authorized use only: scan only hosts and networks you own
 * or have explicit permission to test.
 */

#include <stdlib.h> /* calloc, free, EXIT_SUCCESS */

#include "cli.h"
#include "output.h"
#include "scanner.h"
#include "services.h"
#include "utils.h"

/* Exit codes, documented in the README. */
#define EXIT_SCAN_ERROR 1  /* runtime problem, e.g. the host cannot be resolved */
#define EXIT_USAGE_ERROR 2 /* invalid command-line input */

int main(int argc, char *argv[])
{
    scan_options options;
    parse_status status = parse_arguments(argc, argv, &options);
    if (status == PARSE_EXIT_SUCCESS) {
        return EXIT_SUCCESS;
    }
    if (status == PARSE_ERROR) {
        free_options(&options);
        return EXIT_USAGE_ERROR;
    }

    int exit_code = EXIT_SUCCESS;
    port_result *results = NULL;

    scan_target target;
    if (resolve_target(options.target, &target) != 0) {
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup; /* one shared exit path that frees everything */
    }

    results = calloc(options.port_count, sizeof *results);
    if (results == NULL) {
        print_error("out of memory");
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }
    for (size_t i = 0; i < options.port_count; i++) {
        results[i].port = options.ports[i];
        results[i].state = PORT_NOT_SCANNED;
    }

    scan_report report = {
        .target = options.target,
        .ip_address = target.ip_text,
        .results = results,
        .result_count = options.port_count,
        .started_at = "",
        .duration_ms = 0.0,
        .interrupted = false,
    };
    if (format_utc_timestamp(report.started_at, sizeof report.started_at) != 0) {
        report.started_at[0] = '\0';
    }

    double start_ms = monotonic_time_ms();
    if (scan_port_range(&target, results, options.port_count,
                        options.timeout_ms, options.thread_count) != 0) {
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }
    report.duration_ms = monotonic_time_ms() - start_ms;

    print_result_text(&report);

cleanup:
    close_service_database();
    free(results);
    free_options(&options);
    return exit_code;
}
