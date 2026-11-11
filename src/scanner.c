#include "scanner.h"

#include <arpa/inet.h>  /* inet_ntop, htons */
#include <errno.h>      /* errno, EINPROGRESS, ECONNREFUSED, ... */
#include <fcntl.h>      /* fcntl, O_NONBLOCK */
#include <netdb.h>      /* getaddrinfo, freeaddrinfo, gai_strerror */
#include <poll.h>       /* poll, struct pollfd */
#include <pthread.h>    /* pthread_create, pthread_join, pthread_mutex_* */
#include <stdatomic.h>  /* atomic_bool, atomic_load, atomic_store */
#include <stdbool.h>    /* bool */
#include <stdlib.h>     /* calloc, free */
#include <string.h>     /* memset, memcpy, strerror */
#include <sys/socket.h> /* socket, connect, getsockopt */
#include <unistd.h>     /* close */

#include "utils.h"

/* Longest single poll() wait, so a stop request is noticed quickly. */
#define POLL_SLICE_MS 100

/*
 * Set by the Ctrl+C signal handler, read by every worker thread.
 * A plain bool would be a data race (two threads, one writes, no lock).
 * An atomic variable is safe both across threads and inside a signal
 * handler, because reads and writes happen as one indivisible step.
 */
static atomic_bool stop_requested = false;

void request_scan_stop(void)
{
    atomic_store(&stop_requested, true);
}

bool scan_stop_requested(void)
{
    return atomic_load(&stop_requested);
}

int resolve_target(const char *host, scan_target *target)
{
    /* hints tells getaddrinfo what kind of address we want back. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); /* start with every field zeroed */
    hints.ai_family = AF_INET;       /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM; /* stream socket = TCP */

    struct addrinfo *results = NULL;
    int lookup_result = getaddrinfo(host, NULL, &hints, &results);
    if (lookup_result != 0) {
        print_error("cannot resolve '%s': %s", host, gai_strerror(lookup_result));
        return -1;
    }

    /* Keep only the first address; copy it so we can free the list right away. */
    memset(target, 0, sizeof *target);
    memcpy(&target->address, results->ai_addr, sizeof target->address);
    freeaddrinfo(results);

    /* Binary address -> "127.0.0.1" for display. */
    if (inet_ntop(AF_INET, &target->address.sin_addr,
                  target->ip_text, sizeof target->ip_text) == NULL) {
        print_error("cannot format address of '%s'", host);
        return -1;
    }
    return 0;
}

/* Put the socket into non-blocking mode so connect() returns immediately. */
static int set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0); /* read the current flags first ... */
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK); /* ... then add one flag */
}

/* Map a connect error (errno or SO_ERROR value) to a port state. */
static port_state classify_connect_error(int error_code)
{
    switch (error_code) {
    case 0:
        return PORT_OPEN;
    case ECONNREFUSED: /* RST received */
        return PORT_CLOSED;
    case ETIMEDOUT:    /* kernel gave up waiting */
    case EHOSTUNREACH: /* ICMP "host unreachable", often sent by firewalls */
        return PORT_FILTERED;
    default:
        return PORT_ERROR;
    }
}

/*
 * Start a TCP handshake and wait at most timeout_ms for it to finish.
 * On PORT_ERROR the errno value is stored in *error_code.
 */
static port_state connect_with_timeout(const struct sockaddr_in *address,
                                       int timeout_ms, int *error_code)
{
    *error_code = 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        *error_code = errno;
        return PORT_ERROR;
    }

    if (set_non_blocking(fd) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }

    /*
     * Non-blocking connect: the kernel sends the SYN and returns at once.
     * EINPROGRESS means "handshake started, result comes later".
     */
    if (connect(fd, (const struct sockaddr *)address, sizeof *address) == 0) {
        close(fd); /* connected instantly (can happen on localhost) */
        return PORT_OPEN;
    }
    if (errno != EINPROGRESS) {
        int connect_error = errno; /* save it: close() may change errno */
        port_state state = classify_connect_error(connect_error);
        if (state == PORT_ERROR) {
            *error_code = connect_error;
        }
        close(fd);
        return state;
    }

    /*
     * Wait until the socket becomes writable (handshake finished, either
     * way) or until the timeout expires. Instead of one long poll() we wait
     * in short slices, so a Ctrl+C is noticed within POLL_SLICE_MS even
     * when the timeout is long.
     */
    struct pollfd watch = {.fd = fd, .events = POLLOUT, .revents = 0};
    double deadline_ms = monotonic_time_ms() + timeout_ms;
    for (;;) {
        if (scan_stop_requested()) {
            close(fd);
            return PORT_NOT_SCANNED;
        }
        double remaining_ms = deadline_ms - monotonic_time_ms();
        if (remaining_ms <= 0) {
            close(fd);
            return PORT_FILTERED; /* silence: no SYN-ACK and no RST */
        }
        int wait_ms = remaining_ms > POLL_SLICE_MS ? POLL_SLICE_MS : (int)remaining_ms + 1;

        int ready = poll(&watch, 1, wait_ms);
        if (ready > 0) {
            break; /* handshake finished, result is read below */
        }
        if (ready == -1 && errno != EINTR) {
            *error_code = errno;
            close(fd);
            return PORT_ERROR;
        }
        /* ready == 0 (slice over) or EINTR (a signal arrived): loop again */
    }

    /* The socket is "ready", but did the handshake succeed? Ask the kernel. */
    int socket_error = 0;
    socklen_t length = sizeof socket_error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == -1) {
        *error_code = errno;
        close(fd);
        return PORT_ERROR;
    }
    close(fd);

    port_state state = classify_connect_error(socket_error);
    if (state == PORT_ERROR) {
        *error_code = socket_error;
    }
    return state;
}

port_result scan_port(const scan_target *target, uint16_t port, int timeout_ms)
{
    /* Copy the resolved address and fill in the port for this attempt. */
    struct sockaddr_in address = target->address;
    address.sin_port = htons(port); /* host byte order -> network byte order */

    port_result result = {.port = port, .state = PORT_NOT_SCANNED, .error_code = 0};
    result.state = connect_with_timeout(&address, timeout_ms, &result.error_code);
    return result;
}

/*
 * Shared work queue. All workers read from the same list of ports;
 * next_index says which port is handed out next. Several threads touch
 * next_index, so it is only read or changed while holding 'lock'.
 */
typedef struct {
    const scan_target *target;
    port_result *results; /* each worker writes only the slots it claimed */
    size_t count;
    int timeout_ms;
    size_t next_index; /* protected by lock */
    pthread_mutex_t lock;
} work_queue;

/* Hand out the next unscanned index. Returns false when the work is done. */
static bool take_next_index(work_queue *queue, size_t *index_out)
{
    bool has_work = false;

    if (scan_stop_requested()) {
        return false; /* Ctrl+C: do not start any new port */
    }
    if (pthread_mutex_lock(&queue->lock) != 0) {
        return false; /* cannot happen with a valid mutex; stop this worker */
    }
    /* Only one thread at a time can be between lock and unlock. */
    if (queue->next_index < queue->count) {
        *index_out = queue->next_index;
        queue->next_index++;
        has_work = true;
    }
    pthread_mutex_unlock(&queue->lock);

    return has_work;
}

/* Thread body: keep taking ports from the queue until it is empty. */
static void *scan_worker(void *argument)
{
    work_queue *queue = argument;
    size_t index;

    while (take_next_index(queue, &index)) {
        /* No lock needed here: no other thread ever gets this same index. */
        queue->results[index] = scan_port(queue->target, queue->results[index].port,
                                          queue->timeout_ms);
    }
    return NULL;
}

int scan_port_range(const scan_target *target, port_result *results, size_t count,
                    int timeout_ms, int thread_count)
{
    if (count == 0) {
        return 0;
    }

    work_queue queue = {
        .target = target,
        .results = results,
        .count = count,
        .timeout_ms = timeout_ms,
        .next_index = 0,
    };
    if (pthread_mutex_init(&queue.lock, NULL) != 0) {
        print_error("cannot create mutex");
        return -1;
    }

    /* More threads than ports would only sit idle. */
    size_t wanted = (size_t)thread_count < count ? (size_t)thread_count : count;
    pthread_t *threads = calloc(wanted, sizeof *threads);
    if (threads == NULL) {
        print_error("out of memory");
        pthread_mutex_destroy(&queue.lock);
        return -1;
    }

    size_t started = 0;
    for (size_t i = 0; i < wanted; i++) {
        int error = pthread_create(&threads[i], NULL, scan_worker, &queue);
        if (error != 0) {
            /* Not fatal: the threads already running will share the work. */
            print_error("could only start %zu of %zu threads: %s",
                        started, wanted, strerror(error));
            break;
        }
        started++;
    }

    if (started == 0) {
        scan_worker(&queue); /* no threads at all: do the work ourselves */
    }

    /* Wait for every worker to finish before the results are read. */
    for (size_t i = 0; i < started; i++) {
        int error = pthread_join(threads[i], NULL);
        if (error != 0) {
            print_error("cannot join worker thread: %s", strerror(error));
        }
    }

    free(threads);
    pthread_mutex_destroy(&queue.lock);
    return 0;
}

const char *port_state_to_string(port_state state)
{
    switch (state) {
    case PORT_NOT_SCANNED:
        return "not-scanned";
    case PORT_OPEN:
        return "open";
    case PORT_CLOSED:
        return "closed";
    case PORT_FILTERED:
        return "filtered";
    case PORT_ERROR:
        return "error";
    }
    return "unknown"; /* unreachable, but keeps the compiler happy */
}
