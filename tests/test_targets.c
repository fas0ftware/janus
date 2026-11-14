/*
 * Unit tests for target expansion (lists, CIDR) and banner sanitizing.
 * Prints one line per check; exits non-zero if any check fails.
 */
#include <stdio.h>
#include <string.h>

#include "../src/scanner.h"
#include "../src/targets.h"

static int failures = 0;

#define CHECK(cond, name)                                     \
    do {                                                      \
        if (cond) {                                           \
            printf("PASS: %s\n", name);                       \
        } else {                                              \
            printf("FAIL: %s\n", name);                       \
            failures++;                                       \
        }                                                     \
    } while (0)

static int expands_to(const char *spec, size_t count, const char *first, const char *last)
{
    target_list list;
    if (expand_targets(spec, &list) != 0) {
        return 0;
    }
    int ok = list.count == count && strcmp(list.hosts[0], first) == 0 &&
             strcmp(list.hosts[list.count - 1], last) == 0;
    free_targets(&list);
    return ok;
}

static int rejected(const char *spec)
{
    target_list list;
    int status = expand_targets(spec, &list);
    free_targets(&list);
    return status != 0;
}

int main(void)
{
    CHECK(expands_to("localhost", 1, "localhost", "localhost"), "single host");
    CHECK(expands_to("a.example,b.example,a.example", 2, "a.example", "b.example"), "list without duplicates");
    CHECK(expands_to("192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"), "/24 skips network and broadcast");
    CHECK(expands_to("192.168.1.77/24", 254, "192.168.1.1", "192.168.1.254"), "host bits are ignored");
    CHECK(expands_to("10.0.0.0/30", 2, "10.0.0.1", "10.0.0.2"), "/30 has two hosts");
    CHECK(expands_to("10.0.0.0/31", 2, "10.0.0.0", "10.0.0.1"), "/31 keeps both addresses");
    CHECK(expands_to("10.0.0.9/32", 1, "10.0.0.9", "10.0.0.9"), "/32 is one host");
    CHECK(expands_to("172.16.0.0/20", 4094, "172.16.0.1", "172.16.15.254"), "/20 is the largest block");
    CHECK(expands_to("::1,127.0.0.1", 2, "::1", "127.0.0.1"), "IPv6 literal in a list");
    CHECK(rejected("10.0.0.0/19"), "rejects blocks larger than /20");
    CHECK(rejected("10.0.0.0/33"), "rejects prefix 33");
    CHECK(rejected("10.0.0.0/"), "rejects empty prefix");
    CHECK(rejected("10.0.0.0/2x"), "rejects non-digit prefix");
    CHECK(rejected("10.0.0.0/-1"), "rejects negative prefix");
    CHECK(rejected("300.0.0.0/24"), "rejects bad address");
    CHECK(rejected("fe80::/64"), "rejects IPv6 CIDR");
    CHECK(rejected("a,,b"), "rejects empty list item");
    CHECK(rejected("10.0.0.0/20,10.0.16.0/24"), "rejects more than 4096 hosts in total");

    char out[BANNER_SIZE];
    sanitize_banner("SSH-2.0-OpenSSH_9.6\r\nmore", 25, out, sizeof out);
    CHECK(strcmp(out, "SSH-2.0-OpenSSH_9.6") == 0, "banner keeps the first line");
    sanitize_banner("\r\n  220 ready  \r\n", 16, out, sizeof out);
    CHECK(strcmp(out, "220 ready") == 0, "banner trims blank lines and spaces");
    sanitize_banner("\x1b[31mred\x07\xc3\xa9", 11, out, sizeof out);
    CHECK(strcmp(out, ".[31mred...") == 0, "banner replaces control and non-ASCII bytes");
    char tiny[6];
    sanitize_banner("abcdefghij", 10, tiny, sizeof tiny);
    CHECK(strcmp(tiny, "abcde") == 0, "banner is truncated to the buffer");
    sanitize_banner("a\0b", 3, out, sizeof out);
    CHECK(strcmp(out, "a") == 0, "banner stops at NUL");

    unsigned seen[65536] = {0};
    int duplicate = 0;
    for (int i = 0; i < TOP_PORTS_MAX; i++) {
        duplicate |= seen[top_ports[i]]++ > 0;
    }
    CHECK(!duplicate && top_ports[0] == 80, "top ports are unique and start with 80");

    /* --adaptive: RFC 6298 smoothing and the timeout derived from it. */
    rtt_estimate estimate = {0, 0, 0};
    rtt_add_sample(&estimate, 1.0);
    rtt_add_sample(&estimate, 1.0);
    CHECK(rtt_timeout_ms(&estimate, 1000) == 1000, "adaptive: full timeout until 3 answers were measured");
    rtt_add_sample(&estimate, 1.0);
    CHECK(rtt_timeout_ms(&estimate, 1000) == ADAPTIVE_MIN_MS, "adaptive: a fast LAN host gets the 100 ms floor");
    CHECK(rtt_timeout_ms(&estimate, 50) == 50, "adaptive: never longer than --timeout, even below the floor");
    rtt_estimate slow = {0, 0, 0};
    for (int i = 0; i < 3; i++) {
        rtt_add_sample(&slow, 200.0);
    }
    /* srtt 200, rttvar 100 -> 75 -> 56.25: 200 + 4 * 56.25 = 425 */
    CHECK(slow.samples == 3 && slow.srtt_ms == 200.0 && slow.rttvar_ms == 56.25 && rtt_timeout_ms(&slow, 5000) == 425,
          "adaptive: srtt + 4 * rttvar for a steady 200 ms host");
    CHECK(rtt_timeout_ms(&slow, 300) == 300, "adaptive: clamped to --timeout");
    rtt_estimate jitter = slow;
    rtt_add_sample(&jitter, 800.0);
    CHECK(rtt_timeout_ms(&jitter, 5000) > rtt_timeout_ms(&slow, 5000) + 300,
          "adaptive: one slow answer widens the timeout");

    return failures == 0 ? 0 : 1;
}
