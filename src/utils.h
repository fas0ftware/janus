#ifndef JANUS_UTILS_H
#define JANUS_UTILS_H

#include <stddef.h> /* size_t */

#define JANUS_VERSION "1.0.0"

/* Print "janus: <message>" to stderr, printf-style. */
void print_error(const char *format, ...);

/* Milliseconds from a clock that never jumps backwards (for durations). */
double monotonic_time_ms(void);

/* Write the current UTC time as "YYYY-MM-DDTHH:MM:SSZ". Returns 0 on success. */
int format_utc_timestamp(char *buffer, size_t buffer_size);

#endif /* JANUS_UTILS_H */
