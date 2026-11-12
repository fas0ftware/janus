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
#include "discovery.h"
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

/* Reset one host's results and report. Nothing is resolved or scanned yet. */
static void prepare_host(const char *host, const scan_options *options, port_result *results,
                         scan_report *report)
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
        .status = HOST_STATUS_UNKNOWN,
    };
    if (format_utc_timestamp(report->started_at, sizeof report->started_at) != 0) {
        report->started_at[0] = '\0';
    }
}

/* Resolve the host name once. *target_out keeps the IP text alive. Returns 0 or -1 (message printed). */
static int resolve_host(const char *host, const scan_options *options, scan_target *target_out,
                        scan_report *report)
{
    address_family family = options->family == 4 ? FAMILY_IPV4 : options->family == 6 ? FAMILY_IPV6 : FAMILY_ANY;
    if (resolve_target(host, family, target_out) != 0) {
        return -1;
    }
    report->ip_address = target_out->ip_text;
    report->resolved = true;
    return 0;
}

/*
 * Port-scan a resolved host, unless --discover found it down (then there is
 * nothing to scan and the report stays as prepared). Returns 0, or -2 on a setup error.
 */
static int scan_resolved_host(const scan_options *options, const scan_settings *settings,
                              const scan_target *target, port_result *results, scan_report *report)
{
    if (report->status == HOST_DOWN) {
        return 0;
    }
    double start_ms = monotonic_time_ms();
    if (scan_port_range(target, results, options->port_count, settings) != 0) {
        return -2;
    }
    report->duration_ms = monotonic_time_ms() - start_ms;
    report->interrupted = scan_stop_requested();
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
    bool *resolved_ok = NULL; /* discovery input: which hosts resolved */
    bool *host_up = NULL;     /* discovery output: which hosts answered */

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
    resolved_ok = calloc(targets.count, sizeof *resolved_ok);
    host_up = calloc(targets.count, sizeof *host_up);
    if (resolved == NULL || results == NULL || reports == NULL || resolved_ok == NULL || host_up == NULL) {
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

    double start_ms = monotonic_time_ms();

    /* Step 1: resolve every host (cheap for IP addresses and CIDR blocks). */
    bool any_resolved = false;
    for (size_t h = 0; h < targets.count; h++) {
        prepare_host(targets.hosts[h], &options, results + h * options.port_count, &reports[h]);
    }
    for (size_t h = 0; h < targets.count && !scan_stop_requested(); h++) {
        resolved_ok[h] = resolve_host(targets.hosts[h], &options, &resolved[h], &reports[h]) == 0;
        any_resolved |= resolved_ok[h];
    }

    /* Step 2 (--discover): probe all hosts in parallel and mark the silent ones as down. */
    if (options.discover && !scan_stop_requested()) {
        if (discover_hosts(resolved, resolved_ok, targets.count, options.discover_ports,
                           options.discover_port_count, &settings, host_up) != 0) {
            exit_code = EXIT_SCAN_ERROR;
            goto cleanup;
        }
        /* After Ctrl+C the probes are incomplete, so no host is marked down on that basis. */
        for (size_t h = 0; h < targets.count && !scan_stop_requested(); h++) {
            if (resolved_ok[h]) {
                reports[h].status = host_up[h] ? HOST_UP : HOST_DOWN;
            }
        }
    }

    /* Ctrl+C before any port was scanned: say so in the report (matters for a single host). */
    if (scan_stop_requested()) {
        for (size_t h = 0; h < targets.count; h++) {
            reports[h].interrupted = true;
        }
    }

    /* Step 3: port-scan the hosts one after another (ports of one host run in parallel). */
    size_t scanned_hosts = 0;
    for (size_t h = 0; h < targets.count && !scan_stop_requested(); h++) {
        scanned_hosts++;
        if (!resolved_ok[h]) {
            continue; /* the resolve error was already printed */
        }
        if (scan_resolved_host(&options, &settings, &resolved[h], results + h * options.port_count,
                               &reports[h]) != 0) {
            exit_code = EXIT_SCAN_ERROR;
            goto cleanup;
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
            print_multi_json(reports, scanned_hosts, options.target, started_at, options.discover, duration_ms);
        } else {
            print_multi_text(reports, scanned_hosts, options.open_only, options.discover, duration_ms);
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
    free(host_up);
    free(resolved_ok);
    free(reports);
    free(results);
    free(resolved);
    free_targets(&targets);
    free_options(&options);
    return exit_code;
}
