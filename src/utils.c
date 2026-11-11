#include "utils.h"

#include <stdarg.h> /* va_list, va_start, va_end */
#include <stdio.h>  /* fprintf, vfprintf */
#include <time.h>   /* clock_gettime, time, gmtime_r, strftime */

void print_error(const char *format, ...)
{
    /* The "..." arguments are forwarded to vfprintf through a va_list. */
    va_list args;
    va_start(args, format);
    fprintf(stderr, "janus: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

double monotonic_time_ms(void)
{
    /*
     * CLOCK_MONOTONIC is not affected by someone changing the system
     * clock during the scan, so durations measured with it are reliable.
     */
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0.0;
    }
    return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
}

int format_utc_timestamp(char *buffer, size_t buffer_size)
{
    time_t now = time(NULL);
    struct tm utc;

    /* gmtime_r (not gmtime) writes into our own struct, so it is thread-safe. */
    if (now == (time_t)-1 || gmtime_r(&now, &utc) == NULL) {
        return -1;
    }
    /* strftime returns 0 if the result did not fit into the buffer. */
    if (strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        return -1;
    }
    return 0;
}
