/*
 * Unit tests for the UDP probe payloads (DNS and NTP get a real query,
 * everything else an empty datagram). Prints one line per check; exits
 * non-zero if any check fails.
 */
#include <stdio.h>
#include <string.h>

#include "../src/udp_scan.h"

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

int main(void)
{
    unsigned char buffer[64];

    size_t length = udp_probe_payload(53, buffer, sizeof buffer);
    CHECK(length == 17, "DNS probe is a 17-byte query");
    CHECK(length == 17 && buffer[0] == 0x12 && buffer[1] == 0x34 && buffer[2] == 0x01 && buffer[3] == 0x00,
          "DNS probe has an ID and the recursion-desired flag");
    CHECK(length == 17 && buffer[5] == 0x01 && buffer[11] == 0x00 && buffer[12] == 0x00 && buffer[14] == 0x02 &&
              buffer[16] == 0x01,
          "DNS probe asks one question: root NS, class IN");

    length = udp_probe_payload(123, buffer, sizeof buffer);
    unsigned char zeros[47] = {0};
    CHECK(length == 48 && buffer[0] == 0x1b && memcmp(buffer + 1, zeros, sizeof zeros) == 0,
          "NTP probe is a 48-byte version 3 client request");

    CHECK(udp_probe_payload(161, buffer, sizeof buffer) == 0, "other ports get an empty datagram");
    CHECK(udp_probe_payload(53, buffer, 16) == 0, "DNS probe is not written into a too small buffer");
    CHECK(udp_probe_payload(123, buffer, 47) == 0, "NTP probe is not written into a too small buffer");

    return failures == 0 ? 0 : 1;
}
