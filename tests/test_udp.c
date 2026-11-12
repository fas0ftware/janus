/*
 * Unit tests for the UDP probe payloads (DNS and NTP get a real query,
 * everything else an empty datagram). Prints one line per check; exits
 * non-zero if any check fails.
 */
#define _GNU_SOURCE /* memmem */
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
    unsigned char buffer[128];

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

    /* mDNS: header with one question, then "_services._dns-sd._udp.local" PTR IN. */
    length = udp_probe_payload(5353, buffer, sizeof buffer);
    CHECK(length == 46 && buffer[5] == 0x01 && buffer[12] == 9 && memcmp(buffer + 13, "_services", 9) == 0,
          "mDNS probe asks for _services");
    CHECK(length == 46 && memcmp(buffer + 22, "\x07_dns-sd\x04_udp\x05local\x00", 20) == 0 &&
              buffer[42] == 0x00 && buffer[43] == 0x0c && buffer[44] == 0x00 && buffer[45] == 0x01,
          "mDNS probe is a PTR query for _dns-sd._udp.local");

    /* SSDP: a plain-text M-SEARCH request that ends with an empty line and has no NUL byte. */
    length = udp_probe_payload(1900, buffer, sizeof buffer);
    CHECK(length > 60 && length < 128 && memcmp(buffer, "M-SEARCH * HTTP/1.1\r\n", 21) == 0 &&
              memcmp(buffer + length - 4, "\r\n\r\n", 4) == 0 && memchr(buffer, 0, length) == NULL,
          "SSDP probe is a complete M-SEARCH request");
    CHECK(length > 0 && memmem(buffer, length, "MAN: \"ssdp:discover\"", 20) != NULL, "SSDP probe has the discover header");

    /* NetBIOS: NBSTAT for the wildcard name, encoded as "CK" followed by 30 times 'A'. */
    length = udp_probe_payload(137, buffer, sizeof buffer);
    int netbios_name_ok = length == 50 && buffer[12] == 0x20 && buffer[13] == 'C' && buffer[14] == 'K' &&
                          buffer[45] == 0x00;
    for (size_t i = 15; netbios_name_ok && i < 45; i++) {
        netbios_name_ok = buffer[i] == 'A';
    }
    CHECK(netbios_name_ok && buffer[46] == 0x00 && buffer[47] == 0x21 && buffer[48] == 0x00 && buffer[49] == 0x01,
          "NetBIOS probe is a 50-byte NBSTAT request for the wildcard name");

    CHECK(udp_probe_payload(161, buffer, sizeof buffer) == 0, "SNMP and other ports get an empty datagram");
    CHECK(udp_probe_payload(53, buffer, 16) == 0, "DNS probe is not written into a too small buffer");
    CHECK(udp_probe_payload(123, buffer, 47) == 0, "NTP probe is not written into a too small buffer");
    memset(buffer, 0x55, sizeof buffer);
    CHECK(udp_probe_payload(1900, buffer, 20) == 0 && buffer[0] == 0x55 && buffer[19] == 0x55,
          "SSDP probe writes nothing into a too small buffer");
    CHECK(udp_probe_payload(5353, buffer, 45) == 0 && udp_probe_payload(137, buffer, 49) == 0,
          "mDNS and NetBIOS probes need their full length");

    return failures == 0 ? 0 : 1;
}
