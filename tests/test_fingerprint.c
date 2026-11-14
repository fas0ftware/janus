/*
 * Unit tests for service and version detection (--sv): every matcher gets a
 * realistic reply, a truncated one and a hostile one. Built with
 * AddressSanitizer, so any read past a reply buffer fails the test run.
 * Prints one line per check; exits non-zero if any check fails.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/fingerprint.h"

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

/*
 * Copy the reply into a heap block of exactly its size, so AddressSanitizer
 * reports any read beyond the last byte.
 */
static bool tcp(probe_kind probe, const void *data, size_t length, service_info *out)
{
    unsigned char *copy = malloc(length ? length : 1);
    if (copy == NULL) {
        return false;
    }
    memcpy(copy, data, length);
    bool found = identify_tcp_reply(probe, copy, length, out);
    free(copy);
    return found;
}

static bool udp(uint16_t port, const void *data, size_t length, service_info *out)
{
    unsigned char *copy = malloc(length ? length : 1);
    if (copy == NULL) {
        return false;
    }
    memcpy(copy, data, length);
    bool found = identify_udp_reply(port, copy, length, out);
    free(copy);
    return found;
}

#define TEXT(s) s, sizeof s - 1

static bool is(const service_info *info, const char *service, const char *product, const char *version,
               const char *extra)
{
    bool ok = strcmp(info->service, service) == 0 && strcmp(info->product, product) == 0 &&
              strcmp(info->version, version) == 0 && strcmp(info->info, extra) == 0;
    if (!ok) {
        printf("      got service='%s' product='%s' version='%s' info='%s'\n", info->service, info->product,
               info->version, info->info);
    }
    return ok;
}

static bool is_empty(const service_info *info)
{
    return info->service[0] == '\0' && info->product[0] == '\0' && info->version[0] == '\0' &&
           info->info[0] == '\0';
}

/* Build a TLS record holding a ServerHello; returns its length. */
static size_t server_hello(unsigned char *out, unsigned legacy, unsigned suite, const unsigned char *extensions,
                           size_t extensions_length)
{
    size_t body = 2 + 32 + 1 + 2 + 1 + (extensions ? 2 + extensions_length : 0);
    size_t i = 0;
    out[i++] = 0x16;
    out[i++] = 0x03;
    out[i++] = 0x03;
    out[i++] = (unsigned char)((body + 4) >> 8);
    out[i++] = (unsigned char)(body + 4);
    out[i++] = 0x02;
    out[i++] = 0;
    out[i++] = (unsigned char)(body >> 8);
    out[i++] = (unsigned char)body;
    out[i++] = (unsigned char)(legacy >> 8);
    out[i++] = (unsigned char)legacy;
    memset(out + i, 0x11, 32);
    i += 32;
    out[i++] = 0; /* session id length */
    out[i++] = (unsigned char)(suite >> 8);
    out[i++] = (unsigned char)suite;
    out[i++] = 0; /* compression */
    if (extensions) {
        out[i++] = (unsigned char)(extensions_length >> 8);
        out[i++] = (unsigned char)extensions_length;
        memcpy(out + i, extensions, extensions_length);
        i += extensions_length;
    }
    return i;
}

static void test_ssh(void)
{
    service_info info;
    CHECK(tcp(PROBE_GREETING, TEXT("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"), &info) &&
              is(&info, "ssh", "OpenSSH", "9.6p1", "Ubuntu-3ubuntu13.5"),
          "ssh: OpenSSH with distribution comment");
    CHECK(tcp(PROBE_GREETING, TEXT("SSH-2.0-dropbear_2022.83\r\n"), &info) &&
              is(&info, "ssh", "Dropbear", "2022.83", ""),
          "ssh: Dropbear on a router");
    CHECK(tcp(PROBE_GREETING, TEXT("SSH-2.0-OpenSSH_for_Windows_8.1\r\n"), &info) &&
              is(&info, "ssh", "OpenSSH for Windows", "8.1", ""),
          "ssh: OpenSSH for Windows");
    CHECK(tcp(PROBE_GREETING, TEXT("SSH-1.99-Cisco-1.25\r\n"), &info) &&
              is(&info, "ssh", "Cisco-1.25", "", "protocol 1.99"),
          "ssh: old protocol version is reported");
    CHECK(tcp(PROBE_GREETING, TEXT("SSH-2.0-OpenSSH_9.6"), &info) && is(&info, "ssh", "OpenSSH", "9.6", ""),
          "ssh: greeting without line end");
    CHECK(!tcp(PROBE_GREETING, TEXT("SSH-"), &info) && is_empty(&info), "ssh: bare prefix is not enough");
}

static void test_http(void)
{
    service_info info;
    CHECK(tcp(PROBE_HTTP, TEXT("HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n"), &info) &&
              is(&info, "http", "nginx", "1.24.0", "Ubuntu"),
          "http: nginx with OS comment");
    CHECK(tcp(PROBE_HTTP, TEXT("HTTP/1.1 403 Forbidden\r\nserver:Apache/2.4.58 (Debian) OpenSSL/3.0\r\n\r\n"),
              &info) &&
              is(&info, "http", "Apache", "2.4.58", "(Debian) OpenSSL/3.0"),
          "http: header name is case-insensitive, extra modules kept");
    CHECK(tcp(PROBE_HTTP, TEXT("HTTP/1.0 200 OK\nServer: lighttpd\n\n"), &info) &&
              is(&info, "http", "lighttpd", "", ""),
          "http: bare LF line ends, product without version");
    CHECK(tcp(PROBE_HTTP, TEXT("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\nServer: fake/1\r\n"), &info) &&
              is(&info, "http", "", "", ""),
          "http: a Server line after the headers is ignored");
    CHECK(tcp(PROBE_TLS, TEXT("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n"), &info) &&
              is(&info, "http", "nginx", "", ""),
          "http: plain HTTP answering the TLS probe");
    CHECK(tcp(PROBE_HTTP, TEXT("RTSP/1.0 200 OK\r\nServer: GStreamer RTSP server\r\n\r\n"), &info) &&
              is(&info, "rtsp", "GStreamer", "", "RTSP server"),
          "rtsp: camera stream server");
    CHECK(tcp(PROBE_HTTP, TEXT("HTTP/1.1 200 OK\r\nServer: \x1b]0;pwn\x07" "evil/1\r\n\r\n"), &info) &&
              is(&info, "http", ".]0;pwn.evil", "1", ""),
          "http: escape codes in Server are neutralized");
    char long_reply[400] = "HTTP/1.1 200 OK\r\nServer: ";
    size_t used = strlen(long_reply);
    memset(long_reply + used, 'A', 300);
    memcpy(long_reply + used + 300, "/9\r\n\r\n", 6);
    CHECK(tcp(PROBE_HTTP, long_reply, used + 306, &info) && strlen(info.product) == DETECTED_PRODUCT_SIZE - 1,
          "http: overlong Server header is truncated");
}

static void test_tls(void)
{
    service_info info;
    unsigned char record[128];
    static const unsigned char tls13[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x00};
    size_t length = server_hello(record, 0x0303, 0x1301, tls13, sizeof tls13);
    CHECK(tcp(PROBE_TLS, record, length, &info) && is(&info, "tls", "", "", "TLS 1.3, TLS_AES_128_GCM_SHA256"),
          "tls: TLS 1.3 from supported_versions");
    length = server_hello(record, 0x0303, 0xc02f, NULL, 0);
    CHECK(tcp(PROBE_TLS, record, length, &info) &&
              is(&info, "tls", "", "", "TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256"),
          "tls: TLS 1.2 without extensions");
    length = server_hello(record, 0x0301, 0x002f, NULL, 0);
    CHECK(tcp(PROBE_TLS, record, length, &info) && is(&info, "tls", "", "", "TLS 1.0, AES128-SHA"),
          "tls: outdated TLS 1.0 is visible");
    length = server_hello(record, 0x0303, 0x1302, tls13, sizeof tls13);
    CHECK(tcp(PROBE_TLS, record, 20, &info) && is(&info, "tls", "", "", ""), "tls: truncated ServerHello");
    static const unsigned char lying[] = {0x00, 0x2b, 0xff, 0xff, 0x03, 0x04};
    length = server_hello(record, 0x0303, 0x1301, lying, sizeof lying);
    CHECK(tcp(PROBE_TLS, record, length, &info) && is(&info, "tls", "", "", "TLS 1.2, TLS_AES_128_GCM_SHA256"),
          "tls: extension length beyond the record is not followed");
    record[3] = 0xff; /* record header claims far more than was received */
    CHECK(tcp(PROBE_TLS, record, length, &info) && strcmp(info.service, "tls") == 0,
          "tls: record length beyond the reply is not followed");
    static const unsigned char alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    CHECK(tcp(PROBE_TLS, alert, sizeof alert, &info) && is(&info, "tls", "", "", "alert: handshake_failure"),
          "tls: alert instead of a ServerHello");
    static const unsigned char not_tls[] = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00};
    CHECK(!tcp(PROBE_TLS, not_tls, sizeof not_tls, &info), "tls: an echoed ClientHello is not a server");
}

static void test_tls_probe(void)
{
    unsigned char hello[512];
    size_t length = tls_client_hello(hello, sizeof hello, NULL, false);
    size_t record = (size_t)hello[3] << 8 | hello[4];
    size_t handshake = (size_t)hello[6] << 16 | (size_t)hello[7] << 8 | hello[8];
    CHECK(length > 100 && hello[0] == 0x16 && hello[5] == 0x01 && record == length - 5 && handshake == length - 9,
          "tls probe: record and handshake lengths add up");
    size_t offset = 9 + 2 + 32;
    offset += 1 + hello[offset];                                   /* session id */
    offset += 2 + ((size_t)hello[offset] << 8 | hello[offset + 1]); /* cipher suites */
    offset += 1 + hello[offset];                                   /* compression */
    size_t extensions = (size_t)hello[offset] << 8 | hello[offset + 1];
    CHECK(offset + 2 + extensions == length, "tls probe: extension block ends at the end of the message");
    CHECK(tls_client_hello(hello, 50, NULL, false) == 0, "tls probe: refuses a small buffer");
    unsigned char pg[8];
    static const unsigned char expected[8] = {0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f};
    CHECK(pgsql_ssl_request(pg, sizeof pg) == 8 && memcmp(pg, expected, 8) == 0 && pgsql_ssl_request(pg, 7) == 0,
          "postgresql probe: SSLRequest bytes");
}

static void test_databases(void)
{
    service_info info;
    static const unsigned char mysql[] = "\x4a\x00\x00\x00\x0a" "8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00";
    CHECK(tcp(PROBE_GREETING, mysql, sizeof mysql - 1, &info) &&
              is(&info, "mysql", "MySQL", "8.0.36", "0ubuntu0.22.04.1"),
          "mysql: handshake greeting");
    static const unsigned char maria[] = "\x30\x00\x00\x00\x0a" "5.5.5-10.11.6-MariaDB-0+deb12u1\x00\x01";
    CHECK(tcp(PROBE_GREETING, maria, sizeof maria - 1, &info) &&
              is(&info, "mysql", "MariaDB", "10.11.6", "0+deb12u1"),
          "mysql: MariaDB without the 5.5.5- compatibility prefix");
    static const unsigned char denied[] = "\x45\x00\x00\x00\xff\x6a\x04"
                                          "Host '10.0.0.5' is not allowed to connect to this MySQL server";
    CHECK(tcp(PROBE_GREETING, denied, sizeof denied - 1, &info) && strcmp(info.service, "mysql") == 0 &&
              strstr(info.info, "not allowed") != NULL,
          "mysql: error packet for a refused client");
    static const unsigned char cut[] = "\x4a\x00\x00\x00\x0a" "8.0.36";
    CHECK(!tcp(PROBE_GREETING, cut, sizeof cut - 1, &info) && is_empty(&info),
          "mysql: version without terminating NUL is rejected");
    CHECK(tcp(PROBE_PGSQL, "N", 1, &info) && is(&info, "postgresql", "PostgreSQL", "", "TLS not offered"),
          "postgresql: SSLRequest answered with N");
    CHECK(tcp(PROBE_PGSQL, "S", 1, &info) && is(&info, "postgresql", "PostgreSQL", "", "TLS supported"),
          "postgresql: SSLRequest answered with S");
    CHECK(!tcp(PROBE_GREETING, "S", 1, &info), "postgresql: a lone S without the probe means nothing");
    CHECK(tcp(PROBE_HTTP, TEXT("-ERR unknown command 'HEAD', with args beginning with: '/' 'HTTP/1.0' \r\n"),
              &info) &&
              is(&info, "redis", "Redis", "", ""),
          "redis: unknown command reply");
    CHECK(tcp(PROBE_HTTP, TEXT("-NOAUTH Authentication required.\r\n"), &info) &&
              is(&info, "redis", "Redis", "", "authentication required"),
          "redis: password protected");
    CHECK(tcp(PROBE_HTTP, TEXT("ERROR\r\nERROR\r\n"), &info) && is(&info, "memcached", "", "", ""),
          "memcached: ERROR for every line");
    CHECK(tcp(PROBE_TLS, "AMQP\x00\x00\x09\x01", 8, &info) && is(&info, "amqp", "", "", "protocol 0-9-1"),
          "amqp: broker answers with its protocol header");
}

static void test_text_greetings(void)
{
    service_info info;
    CHECK(tcp(PROBE_GREETING, TEXT("220 (vsFTPd 3.0.5)\r\n"), &info) && is(&info, "ftp", "vsftpd", "3.0.5", ""),
          "ftp: vsftpd");
    CHECK(tcp(PROBE_GREETING, TEXT("220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.2]\r\n"), &info) &&
              is(&info, "ftp", "ProFTPD", "1.3.8", ""),
          "ftp: ProFTPD");
    CHECK(tcp(PROBE_GREETING, TEXT("220-FileZilla Server 1.7.0\r\n220 Please visit https://filezilla-project.org/\r\n"),
              &info) &&
              is(&info, "ftp", "FileZilla Server", "1.7.0", ""),
          "ftp: FileZilla multi-line greeting");
    CHECK(tcp(PROBE_GREETING, TEXT("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"), &info) &&
              is(&info, "smtp", "Postfix", "", ""),
          "smtp: Postfix");
    CHECK(tcp(PROBE_GREETING, TEXT("220 mx.example.org ESMTP Exim 4.96 Thu, 13 Nov 2026 10:00:00 +0000\r\n"), &info) &&
              is(&info, "smtp", "Exim", "4.96", ""),
          "smtp: Exim with version");
    CHECK(tcp(PROBE_GREETING, TEXT("+OK Dovecot (Ubuntu) ready.\r\n"), &info) && is(&info, "pop3", "Dovecot", "", ""),
          "pop3: Dovecot");
    CHECK(tcp(PROBE_GREETING, TEXT("* OK [CAPABILITY IMAP4rev1 LITERAL+] Dovecot ready.\r\n"), &info) &&
              is(&info, "imap", "Dovecot", "", ""),
          "imap: Dovecot");
    CHECK(tcp(PROBE_GREETING, TEXT("220 printer ready\r\n"), &info) == false && is_empty(&info),
          "220 that is neither FTP nor SMTP stays unknown");
    CHECK(tcp(PROBE_GREETING, TEXT("RFB 003.008\n"), &info) && is(&info, "vnc", "", "", "protocol 3.8"),
          "vnc: protocol version");
    CHECK(!tcp(PROBE_GREETING, TEXT("RFB 0x3.008\n"), &info), "vnc: malformed version is rejected");
    CHECK(tcp(PROBE_GREETING, "\xff\xfd\x18\xff\xfd\x20", 6, &info) && is(&info, "telnet", "", "", ""),
          "telnet: option negotiation");
    CHECK(!tcp(PROBE_GREETING, TEXT("hello, world\r\n"), &info) && is_empty(&info), "unknown text stays unknown");
    CHECK(!tcp(PROBE_GREETING, "", 0, &info) && is_empty(&info), "empty reply is unknown");
}

static void test_udp_replies(void)
{
    service_info info;
    static const unsigned char dns[] = {0x12, 0x34, 0x81, 0x85, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1};
    CHECK(udp(53, dns, sizeof dns, &info) && is(&info, "domain", "", "", "recursion available, REFUSED"),
          "dns: flags and response code");
    static const unsigned char not_reply[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    CHECK(!udp(53, not_reply, sizeof not_reply, &info) && is_empty(&info), "dns: a query is not a reply");

    unsigned char ntp[48] = {0x24, 2};
    CHECK(udp(123, ntp, sizeof ntp, &info) && is(&info, "ntp", "", "", "NTPv4, stratum 2"), "ntp: stratum 2 server");
    ntp[1] = 1;
    memcpy(ntp + 12, "GPS", 3);
    CHECK(udp(123, ntp, sizeof ntp, &info) && is(&info, "ntp", "", "", "NTPv4, stratum 1, GPS"),
          "ntp: stratum 1 names its clock");
    CHECK(!udp(123, ntp, 47, &info), "ntp: short packet is rejected");

    unsigned char netbios[12 + 34 + 10 + 1 + 3 * 18 + 6] = {0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0};
    size_t n = 12;
    netbios[n++] = 0x20;
    memset(netbios + n, 'A', 32);
    n += 33;
    n += 10;
    netbios[n++] = 3;
    static const char *const names[] = {"OFFICE-PC      ", "WORKGROUP      ", "OFFICE-PC      "};
    static const unsigned char suffixes[] = {0x00, 0x00, 0x20};
    static const unsigned char flags[] = {0x04, 0x84, 0x04};
    for (int i = 0; i < 3; i++, n += 18) {
        memcpy(netbios + n, names[i], 15);
        netbios[n + 15] = suffixes[i];
        netbios[n + 16] = flags[i];
    }
    CHECK(udp(137, netbios, sizeof netbios, &info) &&
              is(&info, "netbios-ns", "", "", "name OFFICE-PC, group WORKGROUP"),
          "netbios: computer name and workgroup");
    CHECK(udp(137, netbios, 70, &info) && is(&info, "netbios-ns", "", "", ""), "netbios: truncated name table");

    static const char ssdp[] = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n"
                               "SERVER: Linux/5.4 UPnP/1.0 MiniUPnPd/2.2\r\nST: upnp:rootdevice\r\n\r\n";
    CHECK(udp(1900, TEXT(ssdp), &info) && is(&info, "ssdp", "MiniUPnPd", "2.2", "Linux/5.4"),
          "ssdp: router UPnP daemon and OS");

    /*
     * mDNS: two answers "_services._dns-sd._udp.local PTR <type>". The types
     * end in a compression pointer to "local" (offset 35); the second owner
     * name is a pointer to the first one (offset 12).
     */
    unsigned char packet[256];
    size_t p = 0;
    static const unsigned char header[] = {0x12, 0x34, 0x84, 0x00, 0, 0, 0, 2, 0, 0, 0, 0};
    static const unsigned char owner[] = {9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 7, '_', 'd', 'n', 's', '-',
                                          's', 'd', 4, '_', 'u', 'd', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0};
    static const unsigned char rr1[] = {0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 12};
    static const unsigned char ipp[] = {4, '_', 'i', 'p', 'p', 4, '_', 't', 'c', 'p', 0xc0, 35};
    static const unsigned char owner2[] = {0xc0, 12};
    static const unsigned char rr2[] = {0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 13};
    static const unsigned char raop[] = {5, '_', 'r', 'a', 'o', 'p', 4, '_', 't', 'c', 'p', 0xc0, 35};
    const struct {
        const unsigned char *bytes;
        size_t length;
    } parts[] = {{header, sizeof header}, {owner, sizeof owner}, {rr1, sizeof rr1}, {ipp, sizeof ipp},
                 {owner2, sizeof owner2}, {rr2, sizeof rr2},     {raop, sizeof raop}};
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++) {
        memcpy(packet + p, parts[i].bytes, parts[i].length);
        p += parts[i].length;
    }
    CHECK(udp(5353, packet, p, &info) && is(&info, "mdns", "", "", "_ipp._tcp, _raop._tcp"),
          "mdns: advertised service types, with name compression");
    packet[12] = 0xc0; /* owner name now points at itself */
    packet[13] = 12;
    CHECK(udp(5353, packet, p, &info) && is(&info, "mdns", "", "", ""), "mdns: pointer loop is refused");
    CHECK(!udp(9999, dns, sizeof dns, &info) && is_empty(&info), "udp: unprobed ports are never decoded");
}

/*
 * A real certificate, made with:
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650 \
 *     -subj "/O=Janus Test/CN=printer.lan" \
 *     -addext "subjectAltName=DNS:printer.lan,DNS:printer,IP:192.168.1.20"
 */
static const unsigned char test_certificate[] = {
    0x30, 0x82, 0x01, 0xd1, 0x30, 0x82, 0x01, 0x78, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x37,
    0x4d, 0x3a, 0xb4, 0x50, 0x02, 0xd9, 0xad, 0x2c, 0x50, 0xc3, 0x1a, 0x89, 0x23, 0xe7, 0x67, 0xe5,
    0xfb, 0x2f, 0xdf, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x2b, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a, 0x4a, 0x61, 0x6e, 0x75,
    0x73, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0b, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x2e, 0x6c, 0x61, 0x6e, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x31, 0x31, 0x31, 0x34, 0x30, 0x37, 0x32, 0x35, 0x31, 0x32, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x31, 0x31, 0x31, 0x31, 0x30, 0x37, 0x32, 0x35, 0x31, 0x32, 0x5a, 0x30, 0x2b, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a, 0x4a, 0x61, 0x6e, 0x75, 0x73, 0x20, 0x54,
    0x65, 0x73, 0x74, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x70, 0x72,
    0x69, 0x6e, 0x74, 0x65, 0x72, 0x2e, 0x6c, 0x61, 0x6e, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0xf2, 0xe9, 0xea, 0x88, 0xa5, 0xea, 0x47, 0xb5, 0xca, 0x6f, 0x28, 0x7e,
    0x08, 0x8f, 0xf0, 0xb8, 0xcd, 0x20, 0x89, 0x9e, 0x74, 0x98, 0x8b, 0x54, 0xc9, 0x6b, 0xc6, 0x0f,
    0xcb, 0x82, 0xd6, 0x18, 0x8e, 0xfb, 0x2f, 0x7a, 0xe4, 0x7a, 0x18, 0x08, 0x6b, 0x5a, 0x0e, 0x3e,
    0xa2, 0x46, 0x17, 0xbf, 0x38, 0x72, 0x09, 0xca, 0xf3, 0x21, 0x61, 0x27, 0x05, 0xfa, 0xf0, 0x77,
    0xa4, 0x5e, 0x05, 0xbd, 0xa3, 0x7a, 0x30, 0x78, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0x93, 0x03, 0x50, 0xd2, 0x5b, 0x0a, 0x38, 0x31, 0x74, 0x55, 0xdf, 0x2c, 0x01,
    0xdb, 0x31, 0x4d, 0x4e, 0x8a, 0x1b, 0x12, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x93, 0x03, 0x50, 0xd2, 0x5b, 0x0a, 0x38, 0x31, 0x74, 0x55, 0xdf, 0x2c,
    0x01, 0xdb, 0x31, 0x4d, 0x4e, 0x8a, 0x1b, 0x12, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x25, 0x06, 0x03, 0x55, 0x1d, 0x11,
    0x04, 0x1e, 0x30, 0x1c, 0x82, 0x0b, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x2e, 0x6c, 0x61,
    0x6e, 0x82, 0x07, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x87, 0x04, 0xc0, 0xa8, 0x01, 0x14,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30,
    0x44, 0x02, 0x20, 0x5e, 0x93, 0x36, 0x9f, 0xec, 0xbb, 0x64, 0x7d, 0x03, 0xf2, 0x8f, 0x12, 0xc4,
    0xd4, 0xbb, 0x4c, 0xa8, 0x4e, 0xe1, 0x62, 0x0f, 0x3c, 0x8e, 0x22, 0x02, 0x85, 0xa5, 0x23, 0x53,
    0xee, 0x4c, 0x39, 0x02, 0x20, 0x3f, 0xa7, 0xf2, 0x16, 0xc8, 0xb8, 0xe5, 0xbc, 0x5f, 0x14, 0x22,
    0x73, 0xd8, 0x53, 0xa6, 0x66, 0xde, 0x55, 0xac, 0xc5, 0x4c, 0x28, 0x7c, 0x40, 0x6d, 0x6d, 0xba,
    0xcb, 0x2d, 0x21, 0x10, 0xc4

};

/* Find a byte sequence in a buffer; NULL if absent. */
static const unsigned char *find_bytes(const unsigned char *data, size_t length, const void *needle, size_t n)
{
    for (size_t i = 0; i + n <= length; i++) {
        if (memcmp(data + i, needle, n) == 0) {
            return data + i;
        }
    }
    return NULL;
}

static void test_certificates(void)
{
    tls_certificate cert;
    bool ok = parse_certificate(test_certificate, sizeof test_certificate, &cert);
    CHECK(ok && cert.present && strcmp(cert.subject, "printer.lan") == 0, "cert: subject common name");
    CHECK(ok && cert.self_signed && strcmp(cert.issuer, "printer.lan") == 0, "cert: self-signed is detected");
    CHECK(ok && strcmp(cert.not_before, "2026-11-14T07:25:12Z") == 0 && strcmp(cert.not_after, "2036-11-11T07:25:12Z") == 0,
          "cert: validity dates in ISO 8601");
    CHECK(ok && strcmp(cert.key, "EC P-256") == 0, "cert: key type and curve");
    CHECK(ok && cert.name_count == 3 && strcmp(cert.names[0], "printer.lan") == 0 &&
              strcmp(cert.names[1], "printer") == 0 && strcmp(cert.names[2], "192.168.1.20") == 0,
          "cert: subjectAltName DNS names and IP address");
    CHECK(!certificate_expired(&cert, "2030-01-01T00:00:00Z") && certificate_expired(&cert, "2036-11-11T07:25:13Z"),
          "cert: expired one second after notAfter");
    CHECK(certificate_not_yet_valid(&cert, "2026-11-14T07:25:11Z") &&
              !certificate_not_yet_valid(&cert, "2026-11-14T07:25:12Z"),
          "cert: not yet valid before notBefore");
    CHECK(!certificate_expired(&cert, ""), "cert: unknown current time never counts as expired");

    /* Every truncation must be rejected cleanly (ASan checks that nothing is read past the end). */
    bool all_rejected = true;
    for (size_t n = 0; n < sizeof test_certificate; n++) {
        unsigned char *copy = malloc(n ? n : 1);
        memcpy(copy, test_certificate, n);
        all_rejected &= !parse_certificate(copy, n, &cert) && !cert.present;
        free(copy);
    }
    CHECK(all_rejected, "cert: every truncated prefix is rejected");

    /* Flip every byte to a few hostile values: parsing may fail, but must stay in bounds and terminate. */
    unsigned char *mutated = malloc(sizeof test_certificate);
    static const unsigned char values[] = {0x00, 0x7f, 0x80, 0x83, 0xff};
    bool printable = true;
    size_t parsed = 0;
    for (size_t i = 0; i < sizeof test_certificate; i++) {
        for (size_t v = 0; v < sizeof values; v++) {
            memcpy(mutated, test_certificate, sizeof test_certificate);
            mutated[i] = values[v];
            if (parse_certificate(mutated, sizeof test_certificate, &cert)) {
                parsed++;
                const char *texts[] = {cert.subject, cert.issuer, cert.key, cert.names[0]};
                for (size_t t = 0; t < 4; t++) {
                    for (const char *c = texts[t]; *c; c++) {
                        printable &= *c >= 0x20 && *c < 0x7f;
                    }
                }
            }
        }
    }
    free(mutated);
    CHECK(parsed > 0 && printable, "cert: 2345 corrupted certificates parse in bounds, text stays printable");

    /* A TLS 1.2 flight: ServerHello in one record, the Certificate message split over two records. */
    unsigned char flight[2048];
    unsigned char hello[128];
    size_t hello_length = server_hello(hello, 0x0303, 0xc02b, NULL, 0);
    size_t f = 0;
    memcpy(flight, hello, hello_length);
    f = hello_length;
    unsigned char message[1024];
    size_t m = 0;
    size_t list = 3 + sizeof test_certificate;
    message[m++] = 11;
    message[m++] = 0;
    message[m++] = (unsigned char)((list + 3) >> 8);
    message[m++] = (unsigned char)(list + 3);
    message[m++] = 0;
    message[m++] = (unsigned char)(list >> 8);
    message[m++] = (unsigned char)list;
    message[m++] = 0;
    message[m++] = (unsigned char)(sizeof test_certificate >> 8);
    message[m++] = (unsigned char)sizeof test_certificate;
    memcpy(message + m, test_certificate, sizeof test_certificate);
    m += sizeof test_certificate;
    size_t half = m / 2;
    const size_t pieces[2][2] = {{0, half}, {half, m - half}};
    for (int i = 0; i < 2; i++) {
        flight[f++] = 0x16;
        flight[f++] = 0x03;
        flight[f++] = 0x03;
        flight[f++] = (unsigned char)(pieces[i][1] >> 8);
        flight[f++] = (unsigned char)pieces[i][1];
        memcpy(flight + f, message + pieces[i][0], pieces[i][1]);
        f += pieces[i][1];
    }
    service_info info;
    CHECK(tcp(PROBE_TLS, flight, f, &info) && info.certificate.present &&
              strcmp(info.certificate.subject, "printer.lan") == 0 &&
              strcmp(info.info, "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256") == 0,
          "tls: certificate reassembled from two records");
    CHECK(tls_reply_complete(flight, f), "tls: reply with the whole certificate is complete");
    CHECK(!tls_reply_complete(flight, f - 1), "tls: one byte short of the certificate: keep reading");
    CHECK(!tls_reply_complete(flight, hello_length), "tls: TLS 1.2 ServerHello alone: wait for the certificate");
    CHECK(tcp(PROBE_TLS, flight, f - 40, &info) && strcmp(info.service, "tls") == 0 && !info.certificate.present,
          "tls: truncated certificate is not reported");
    static const unsigned char tls13[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    hello_length = server_hello(hello, 0x0303, 0x1301, tls13, sizeof tls13);
    CHECK(tls_reply_complete(hello, hello_length) && !tls_reply_complete(hello, hello_length - 1),
          "tls: TLS 1.3 is complete after the ServerHello");
    static const unsigned char alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46};
    CHECK(tls_reply_complete(alert, sizeof alert), "tls: an alert is complete");

    unsigned char probe[512];
    size_t length = tls_client_hello(probe, sizeof probe, "printer.lan", false);
    CHECK(length > 0 && find_bytes(probe, length, "\x00\x00\x00\x10\x00\x0e\x00\x00\x0bprinter.lan", 16) != NULL,
          "tls probe: host name is sent as SNI");
    length = tls_client_hello(probe, sizeof probe, "192.168.1.20", false);
    CHECK(length > 0 && find_bytes(probe, length, "192.168", 7) == NULL, "tls probe: IP addresses are never sent as SNI");
    length = tls_client_hello(probe, sizeof probe, "evil\r\nname", false);
    CHECK(length > 0 && find_bytes(probe, length, "evil", 4) == NULL, "tls probe: invalid names are not sent");
    length = tls_client_hello(probe, sizeof probe, NULL, true);
    size_t record = (size_t)probe[3] << 8 | probe[4];
    CHECK(length > 0 && record == length - 5 && find_bytes(probe, length, "\x00\x2b\x00", 3) == NULL &&
              find_bytes(probe, length, "\x13\x01", 2) == NULL,
          "tls probe: TLS 1.2-only hello offers no 1.3 version or suites");
}

static void test_starttls_replies(void)
{
    CHECK(line_reply_complete((const unsigned char *)"220 ready\r\n", 11), "lines: single coded line is complete");
    CHECK(!line_reply_complete((const unsigned char *)"220 rea", 7), "lines: unfinished line is not");
    CHECK(!line_reply_complete((const unsigned char *)"250-mail\r\n250-STARTTLS\r\n", 24),
          "lines: SMTP continuation lines wait for the final line");
    CHECK(line_reply_complete((const unsigned char *)"250-mail\r\n250 8BITMIME\r\n", 24),
          "lines: SMTP reply ends with 'code space'");
    CHECK(line_reply_complete((const unsigned char *)"+OK hi\r\n", 8), "lines: uncoded text ends with the first line");
    static const char imap[] = "* NOTE x\r\nJ1 OK go\r\n";
    CHECK(!tagged_reply_complete((const unsigned char *)imap, 10, "J1") &&
              tagged_reply_complete((const unsigned char *)imap, sizeof imap - 1, "J1"),
          "imap: the tagged line ends the reply");
    CHECK(!tagged_reply_complete((const unsigned char *)"J10 OK\r\n", 8, "J1"), "imap: a longer tag does not match");
    static const char ehlo[] = "250-mail.test\r\n250-PIPELINING\r\n250-starttls\r\n250 8BITMIME\r\n";
    CHECK(smtp_offers_starttls((const unsigned char *)ehlo, sizeof ehlo - 1), "smtp: STARTTLS found in EHLO reply");
    static const char no_tls[] = "250-mail.test\r\n250-XSTARTTLSX\r\n250 8BITMIME\r\n";
    CHECK(!smtp_offers_starttls((const unsigned char *)no_tls, sizeof no_tls - 1),
          "smtp: only an exact STARTTLS line counts");
    static const char last[] = "250 STARTTLS";
    CHECK(smtp_offers_starttls((const unsigned char *)last, sizeof last - 1), "smtp: STARTTLS on the final line");
    service_info info;
    CHECK(tcp(PROBE_GREETING, TEXT("220-Welcome to our server\r\n220 (vsFTPd 3.0.5)\r\n"), &info) &&
              is(&info, "ftp", "vsftpd", "3.0.5", ""),
          "ftp: product on the second line of a multi-line greeting");
}

static void test_format(void)
{
    char out[160];
    service_info info = {.service = "ssh", .product = "OpenSSH", .version = "9.6p1", .info = "Ubuntu"};
    format_detected_version(&info, out, sizeof out);
    CHECK(strcmp(out, "OpenSSH 9.6p1 (Ubuntu)") == 0, "format: product, version and info");
    service_info tls = {.service = "tls", .info = "TLS 1.3"};
    format_detected_version(&tls, out, sizeof out);
    CHECK(strcmp(out, "TLS 1.3") == 0, "format: info alone has no parentheses");
    service_info bare = {.service = "telnet"};
    format_detected_version(&bare, out, sizeof out);
    CHECK(strcmp(out, "") == 0, "format: nothing beyond the service name");
    char small[8];
    format_detected_version(&info, small, sizeof small);
    CHECK(strcmp(small, "OpenSSH") == 0, "format: truncated to the buffer");
}

int main(void)
{
    test_ssh();
    test_http();
    test_tls();
    test_tls_probe();
    test_certificates();
    test_starttls_replies();
    test_databases();
    test_text_greetings();
    test_udp_replies();
    test_format();
    return failures == 0 ? 0 : 1;
}
