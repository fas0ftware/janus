#include "discovery.h"

#include <pthread.h>   /* pthread_create, pthread_join */
#include <stdatomic.h> /* atomic_bool, atomic_size_t, atomic_fetch_add */
#include <stdlib.h>    /* calloc, free */
#include <string.h>    /* strerror */

#include "utils.h"

/*
 * Shared state of all discovery workers.
 *
 * The jobs are (probe port, host) pairs, numbered probe-major: job 0..H-1
 * is the first probe port on every host, the next H jobs the second probe
 * port, and so on. Hosts that answer early are therefore skipped for all
 * later probe ports, and only silent hosts pay for every probe.
 */
typedef struct {
    const scan_target *targets;
    const bool *eligible;
    size_t host_count;
    const uint16_t *probe_ports;
    size_t job_count;
    const scan_settings *settings; /* grab_banner is always false here */
    atomic_size_t next_job;        /* each worker claims jobs with fetch_add */
    atomic_bool *alive;            /* one flag per host, set by whichever worker sees an answer */
} discovery_queue;

/* Thread body: claim jobs until none are left or Ctrl+C was pressed. */
static void *discovery_worker(void *argument)
{
    discovery_queue *queue = argument;

    while (!scan_stop_requested()) {
        /* fetch_add hands out every job number to exactly one thread, no mutex needed. */
        size_t job = atomic_fetch_add(&queue->next_job, 1);
        if (job >= queue->job_count) {
            break;
        }
        size_t host = job % queue->host_count;
        size_t probe = job / queue->host_count;
        if (!queue->eligible[host] || atomic_load(&queue->alive[host])) {
            continue; /* unresolved, or already known to be up */
        }

        port_result result = scan_port(&queue->targets[host], queue->probe_ports[probe], queue->settings);
        /* SYN-ACK and RST both prove that a machine answered. */
        if (result.state == PORT_OPEN || result.state == PORT_CLOSED) {
            atomic_store(&queue->alive[host], true);
        }
    }
    return NULL;
}

int discover_hosts(const scan_target *targets, const bool *eligible, size_t host_count,
                   const uint16_t *probe_ports, size_t probe_count, const scan_settings *settings,
                   bool *up)
{
    for (size_t i = 0; i < host_count; i++) {
        up[i] = false;
    }
    if (host_count == 0 || probe_count == 0) {
        return 0;
    }

    /* Probing never reads banners, whatever the main scan will do. */
    scan_settings probe_settings = *settings;
    probe_settings.grab_banner = false;

    discovery_queue queue = {
        .targets = targets,
        .eligible = eligible,
        .host_count = host_count,
        .probe_ports = probe_ports,
        .job_count = host_count * probe_count,
        .settings = &probe_settings,
    };
    atomic_init(&queue.next_job, 0);
    queue.alive = calloc(host_count, sizeof *queue.alive);
    if (queue.alive == NULL) {
        print_error("out of memory");
        return -1;
    }
    for (size_t i = 0; i < host_count; i++) {
        atomic_init(&queue.alive[i], false);
    }

    /* More threads than jobs would only sit idle. */
    size_t wanted = (size_t)settings->thread_count < queue.job_count ? (size_t)settings->thread_count
                                                                      : queue.job_count;
    pthread_t *threads = calloc(wanted, sizeof *threads);
    if (threads == NULL) {
        print_error("out of memory");
        free(queue.alive);
        return -1;
    }

    size_t started = 0;
    for (size_t i = 0; i < wanted; i++) {
        int error = pthread_create(&threads[i], NULL, discovery_worker, &queue);
        if (error != 0) {
            /* Not fatal: the threads already running will share the work. */
            print_error("could only start %zu of %zu discovery threads: %s", started, wanted,
                        strerror(error));
            break;
        }
        started++;
    }
    if (started == 0) {
        discovery_worker(&queue); /* no threads at all: do the work ourselves */
    }

    for (size_t i = 0; i < started; i++) {
        int error = pthread_join(threads[i], NULL);
        if (error != 0) {
            print_error("cannot join discovery thread: %s", strerror(error));
        }
    }

    /* All workers are done, so plain reads of the flags are safe now. */
    for (size_t i = 0; i < host_count; i++) {
        up[i] = atomic_load(&queue.alive[i]);
    }
    free(threads);
    free(queue.alive);
    return 0;
}
