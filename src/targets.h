#ifndef JANUS_TARGETS_H
#define JANUS_TARGETS_H

#include <stddef.h> /* size_t */
#include <stdint.h> /* uint16_t */

/* A CIDR block may expand to at most this many hosts (/20 = 4094 usable). */
#define MAX_TARGET_HOSTS 4096
/* Smallest prefix accepted for IPv4 CIDR blocks. */
#define MIN_CIDR_PREFIX 20

/* Hosts to scan, in the order given. Each string is heap allocated. */
typedef struct {
    char **hosts;
    size_t count;
} target_list;

/*
 * Expand "host", "a,b,c" and IPv4 CIDR blocks such as "192.168.1.0/24".
 * For prefixes up to /30 the network and broadcast addresses are skipped;
 * /31 and /32 keep every address. Duplicates are removed. Returns 0 or -1
 * (an error message was printed). Call free_targets() afterwards.
 */
int expand_targets(const char *spec, target_list *out);

void free_targets(target_list *list);

/* The most commonly open TCP ports, most common first. */
#define TOP_PORTS_MAX 100
extern const uint16_t top_ports[TOP_PORTS_MAX];

#endif /* JANUS_TARGETS_H */
