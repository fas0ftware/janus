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
#include "targets.h"
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

/* One host: prepare its results and report, then resolve it. Returns 0 if resolved. */
static int prepare_host(const char *host, const scan_options *options, scan_target *target_out,
                        port_result *results, scan_report *report)
{
    for (size_t i = 0; i < options->port_count; i++) {
        memset(&results[i], 0, sizeof results[i]);
        results[i].port = options->ports[i];
        results[i].state = PORT_NOT_SCANNED;
    }
    *report = (scan_report){
        .target = host,
        .ip_address = "",
        .results = results,
        .result_count = options->port_count,
        .started_at = "",
        .duration_ms = 0.0,
        .interrupted = false,
        .show_banner = options->grab_banner,
        .resolved = false,
    };
    if (format_utc_timestamp(report->started_at, sizeof report->started_at) != 0) {
        report->started_at[0] = '\0';
    }

    address_family family = options->family == 4 ? FAMILY_IPV4 : options->family == 6 ? FAMILY_IPV6 : FAMILY_ANY;
    if (resolve_target(host, family, target_out) != 0) {
        return -1;
    }
    report->ip_address = target_out->ip_text;
    report->resolved = true;
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
    target_list targets = {NULL, 0};
    scan_target *resolved = NULL;
    port_result *results = NULL;
    scan_report *reports = NULL;
    host_job *jobs = NULL;

    if (expand_targets(options.target, &targets) != 0) {
        free_options(&options);
        return EXIT_USAGE_ERROR;
    }
    if (install_signal_handlers() != 0) {
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }

    /* One results block per host: count * ports entries, allocated once. */
    resolved = calloc(targets.count, sizeof *resolved);
    results = calloc(targets.count * options.port_count, sizeof *results);
    reports = calloc(targets.count, sizeof *reports);
    if (resolved == NULL || results == NULL || reports == NULL) {
        print_error("out of memory (%zu hosts x %zu ports)", targets.count, options.port_count);
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }

    scan_settings settings = {
        .timeout_ms = options.timeout_ms,
        .thread_count = options.thread_count,
        .grab_banner = options.grab_banner,
    };
    char started_at[TIMESTAMP_SIZE] = "";
    if (format_utc_timestamp(started_at, sizeof started_at) != 0) {
        started_at[0] = '\0';
    }

    /*
     * Resolve every target first, then scan all of them with one shared
     * worker pool: a block of silent addresses is probed in parallel instead
     * of one host after another.
     */
    double start_ms = monotonic_time_ms();
    size_t scanned_hosts = 0;
    bool any_resolved = false;
    jobs = calloc(targets.count, sizeof *jobs);
    if (jobs == NULL) {
        print_error("out of memory");
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }
    for (size_t h = 0; h < targets.count && !scan_stop_requested(); h++) {
        port_result *block = results + h * options.port_count;
        if (prepare_host(targets.hosts[h], &options, &resolved[h], block, &reports[h]) == 0) {
            jobs[h].target = &resolved[h];
            any_resolved = true;
        }
        jobs[h].results = block;
        scanned_hosts++;
    }
    double scan_start_ms = monotonic_time_ms();
    if (scan_hosts(jobs, scanned_hosts, options.port_count, &settings) != 0) {
        exit_code = EXIT_SCAN_ERROR;
        goto cleanup;
    }
    for (size_t h = 0; h < scanned_hosts; h++) {
        if (reports[h].resolved) {
            /* Hosts run side by side: each one's time runs from the scan start to its last port. */
            double finished = jobs[h].finished_ms > 0.0 ? jobs[h].finished_ms : scan_start_ms;
            reports[h].duration_ms = finished - scan_start_ms;
            reports[h].interrupted = scan_stop_requested();
        }
    }
    double duration_ms = monotonic_time_ms() - start_ms;
    bool interrupted = scan_stop_requested();

    if (targets.count == 1) {
        if (!reports[0].resolved) {
            exit_code = EXIT_SCAN_ERROR; /* the error was already printed */
            goto cleanup;
        }
        if (options.json_output) {
            print_result_json(&reports[0]);
        } else {
            print_result_text(&reports[0]);
        }
    } else {
        if (options.json_output) {
            print_multi_json(reports, scanned_hosts, options.target, started_at, duration_ms);
        } else {
            print_multi_text(reports, scanned_hosts, options.open_only, duration_ms);
        }
        if (!any_resolved) {
            exit_code = EXIT_SCAN_ERROR;
        }
        if (interrupted) {
            print_error("scan interrupted after %zu of %zu host(s), results are partial", scanned_hosts,
                        targets.count);
        }
    }

    /*
     * printf only fills a buffer; a full disk or a closed pipe shows up
     * when the buffer is flushed. Check it so failures are not silent.
     */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        print_error("cannot write output: %s", strerror(errno));
        exit_code = EXIT_SCAN_ERROR;
    } else if (interrupted) {
        exit_code = EXIT_INTERRUPTED;
    }

cleanup:
    close_service_database();
    free(jobs);
    free(reports);
    free(results);
    free(resolved);
    free_targets(&targets);
    free_options(&options);
    return exit_code;
}
