/*
 * Janus - a simple TCP connect port scanner for Linux.
 *
 * Authorized use only: scan only hosts and networks you own
 * or have explicit permission to test.
 */

#include <errno.h>  /* errno */
#include <signal.h> /* sigaction, SIGINT, SIGTERM */
#include <stdio.h>  /* fflush, ferror, stdout */
#include <stdlib.h> /* calloc, free, EXIT_SUCCESS */
#include <string.h> /* memset, strerror */

#include "cli.h"
#include "output.h"
#include "scanner.h"
#include "services.h"
#include "utils.h"

/* Exit codes, documented in the README. */
#define EXIT_SCAN_ERROR 1  /* runtime problem, e.g. the host cannot be resolved */
#define EXIT_USAGE_ERROR 2 /* invalid command-line input */
#define EXIT_INTERRUPTED 130 /* shell convention: 128 + SIGINT (2) */

/*
 * Runs when the user presses Ctrl+C (SIGINT) or the process gets SIGTERM.
 * A signal handler may interrupt the program anywhere, even inside printf
 * or malloc, so it must only do async-signal-safe work: here it just sets
 * an atomic flag. The scan loop sees the flag and stops cleanly.
 */
static void handle_stop_signal(int signal_number)
{
    (void)signal_number;
    request_scan_stop();
}

static int install_signal_handlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handle_stop_signal;
    sigemptyset(&action.sa_mask);
    /*
     * SA_RESETHAND: after the first signal the default action comes back,
     * so a second Ctrl+C kills Janus immediately if a clean stop hangs.
     */
    action.sa_flags = SA_RESETHAND;

    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        print_error("cannot install signal handler: %s", strerror(errno));
        return -1;
    }
    return 0;
}

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

    if (install_signal_handlers() != 0) {
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }

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
    report.interrupted = scan_stop_requested();

    if (options.json_output) {
        print_result_json(&report);
    } else {
        print_result_text(&report);
    }

    /*
     * printf only fills a buffer; a full disk or a closed pipe shows up
     * when the buffer is flushed. Check it so failures are not silent.
     */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        print_error("cannot write output: %s", strerror(errno));
        exit_code = EXIT_SCAN_ERROR;
    } else if (report.interrupted) {
        exit_code = EXIT_INTERRUPTED;
    }

cleanup:
    close_service_database();
    free(results);
    free_options(&options);
    return exit_code;
}
