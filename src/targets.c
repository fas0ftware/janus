#include "targets.h"

#include <arpa/inet.h> /* inet_pton, inet_ntop, htonl, ntohl */
#include <stdbool.h>   /* bool */
#include <stdlib.h>    /* calloc, free, malloc */
#include <string.h>    /* memcpy, strchr, strcmp, strlen */

#include "cli.h"   /* MAX_TARGET_LENGTH */
#include "utils.h" /* print_error */

/* Roughly the order of nmap's frequency table: the most often open ports first. */
const uint16_t top_ports[TOP_PORTS_MAX] = {
    80,    23,    443,   21,    22,    25,    3389,  110,   445,   139,   143,   53,    135,
    3306,  8080,  1723,  111,   995,   993,   5900,  1025,  587,   8888,  199,   1720,  465,
    548,   113,   81,    6001,  10000, 514,   5060,  179,   1026,  2000,  8443,  8000,  32768,
    554,   26,    1433,  49152, 2001,  515,   8008,  49154, 1027,  5666,  646,   5000,  5631,
    631,   49153, 8081,  2049,  88,    79,    5800,  106,   2121,  1110,  49155, 6000,  513,
    990,   5357,  427,   49156, 543,   544,   5101,  144,   7,     389,   8009,  3128,  444,
    9999,  5009,  7070,  5190,  3000,  5432,  1900,  3986,  13,    1029,  9,     5051,  6646,
    49157, 1028,  873,   1755,  2717,  4899,  9100,  119,   37,
};

/* UDP services that answer scans or show up on home and office networks. */
const uint16_t udp_top_ports[UDP_TOP_PORTS_MAX] = {
    53,   123,  161,  137,  138,  67,   68,   69,   500,  514,
    520,  631,  1434, 1701, 1900, 4500, 5060, 5353, 162,  11211,
};

static int add_host(target_list *list, size_t capacity, const char *host)
{
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->hosts[i], host) == 0) {
            return 0; /* duplicate: keep the first one */
        }
    }
    if (list->count >= capacity) {
        print_error("too many targets (at most %d hosts per run)", MAX_TARGET_HOSTS);
        return -1;
    }
    size_t length = strlen(host);
    char *copy = malloc(length + 1);
    if (copy == NULL) {
        print_error("out of memory");
        return -1;
    }
    memcpy(copy, host, length + 1);
    list->hosts[list->count++] = copy;
    return 0;
}

/* "192.168.1.0/24" -> every host address in the block. */
static int add_cidr(target_list *list, size_t capacity, const char *item)
{
    const char *slash = strchr(item, '/');
    char address_text[INET_ADDRSTRLEN];
    size_t address_length = (size_t)(slash - item);
    if (address_length == 0 || address_length >= sizeof address_text) {
        print_error("invalid CIDR block '%s'", item);
        return -1;
    }
    memcpy(address_text, item, address_length);
    address_text[address_length] = '\0';

    struct in_addr base;
    if (inet_pton(AF_INET, address_text, &base) != 1) {
        print_error("invalid CIDR block '%s' (only IPv4 blocks are supported)", item);
        return -1;
    }

    /* Prefix: 1-2 digits, nothing else. */
    const char *digits = slash + 1;
    size_t digit_count = strlen(digits);
    if (digit_count == 0 || digit_count > 2 || digits[0] < '0' || digits[0] > '9' ||
        (digit_count == 2 && (digits[1] < '0' || digits[1] > '9'))) {
        print_error("invalid prefix in '%s'", item);
        return -1;
    }
    int prefix = digits[0] - '0';
    if (digit_count == 2) {
        prefix = prefix * 10 + (digits[1] - '0');
    }
    if (prefix > 32) {
        print_error("invalid prefix in '%s' (IPv4 prefixes are 0-32)", item);
        return -1;
    }
    if (prefix < MIN_CIDR_PREFIX) {
        print_error("CIDR block '%s' is too large: use /%d to /32 (at most %d hosts)", item,
                    MIN_CIDR_PREFIX, MAX_TARGET_HOSTS);
        return -1;
    }

    uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    uint32_t network = ntohl(base.s_addr) & mask;
    uint32_t last = network | ~mask;
    uint32_t first_host = network, last_host = last;
    if (prefix <= 30) {
        first_host++; /* skip the network address */
        last_host--;  /* and the broadcast address */
    }

    for (uint64_t value = first_host; value <= last_host; value++) {
        struct in_addr host_address = {.s_addr = htonl((uint32_t)value)};
        char host_text[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &host_address, host_text, sizeof host_text) == NULL ||
            add_host(list, capacity, host_text) != 0) {
            return -1;
        }
    }
    return 0;
}

int expand_targets(const char *spec, target_list *out)
{
    out->hosts = NULL;
    out->count = 0;
    size_t capacity = MAX_TARGET_HOSTS;
    out->hosts = calloc(capacity, sizeof *out->hosts);
    if (out->hosts == NULL) {
        print_error("out of memory");
        return -1;
    }

    const char *item_start = spec;
    for (;;) {
        const char *comma = strchr(item_start, ',');
        size_t length = comma != NULL ? (size_t)(comma - item_start) : strlen(item_start);
        if (length == 0 || length > MAX_TARGET_LENGTH) {
            print_error("empty or too long target in '%s'", spec);
            free_targets(out);
            return -1;
        }
        char item[MAX_TARGET_LENGTH + 1];
        memcpy(item, item_start, length);
        item[length] = '\0';

        int status = strchr(item, '/') != NULL ? add_cidr(out, capacity, item) : add_host(out, capacity, item);
        if (status != 0) {
            free_targets(out);
            return -1;
        }
        if (comma == NULL) {
            break;
        }
        item_start = comma + 1;
    }
    return 0;
}

void free_targets(target_list *list)
{
    if (list->hosts != NULL) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->hosts[i]);
        }
        free(list->hosts);
    }
    list->hosts = NULL;
    list->count = 0;
}
