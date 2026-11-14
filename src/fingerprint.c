#include "fingerprint.h"

#include <arpa/inet.h> /* inet_ntop */
#include <sys/socket.h> /* AF_INET, AF_INET6 */
#include <stdio.h>   /* snprintf */
#include <string.h>  /* memset, memcpy, strlen */
#include <strings.h> /* strncasecmp */

/* ---- small text helpers ------------------------------------------------------ */

static bool is_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

/*
 * Copy untrusted bytes into a C string: surrounding blanks are trimmed and
 * every byte outside printable ASCII becomes '.', exactly like banners.
 */
static void copy_text(char *out, size_t out_size, const unsigned char *source, size_t length)
{
    if (out_size == 0) {
        return;
    }
    while (length > 0 && is_space(*source)) {
        source++;
        length--;
    }
    while (length > 0 && is_space(source[length - 1])) {
        length--;
    }
    size_t written = 0;
    for (size_t i = 0; i < length && written + 1 < out_size; i++) {
        unsigned char c = source[i];
        out[written++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[written] = '\0';
}

static void set_text(char *out, size_t out_size, const char *text)
{
    copy_text(out, out_size, (const unsigned char *)text, strlen(text));
}

/* Append "<separator><text>" (just <text> if out is empty), truncating at out_size. */
static void append_text(char *out, size_t out_size, const char *separator, const char *text)
{
    if (text[0] == '\0' || out_size == 0) {
        return;
    }
    size_t used = strlen(out);
    const char *parts[2] = {used > 0 ? separator : "", text};
    for (size_t p = 0; p < 2; p++) {
        for (const char *c = parts[p]; *c != '\0' && used + 1 < out_size; c++) {
            out[used++] = *c;
        }
    }
    out[used] = '\0';
}

static bool has_prefix(const unsigned char *data, size_t length, const char *prefix)
{
    size_t prefix_length = strlen(prefix);
    return length >= prefix_length && memcmp(data, prefix, prefix_length) == 0;
}

/* Length of the first line (up to, not including, CR or LF). */
static size_t line_length(const unsigned char *data, size_t length)
{
    size_t i = 0;
    while (i < length && data[i] != '\r' && data[i] != '\n') {
        i++;
    }
    return i;
}

/* Find needle in data[0..length-1]; case-insensitive if ignore_case. NULL if absent. */
static const unsigned char *find_text(const unsigned char *data, size_t length, const char *needle, bool ignore_case)
{
    size_t needle_length = strlen(needle);
    if (needle_length == 0 || needle_length > length) {
        return NULL;
    }
    for (size_t i = 0; i + needle_length <= length; i++) {
        bool match = ignore_case ? strncasecmp((const char *)data + i, needle, needle_length) == 0
                                 : memcmp(data + i, needle, needle_length) == 0;
        /*
         * strncasecmp stops at a NUL in data, which can only make it report a
         * mismatch, so it never reads past needle_length bytes of data.
         */
        if (match) {
            return data + i;
        }
    }
    return NULL;
}

/*
 * Read a version number that starts at *cursor (after optional blanks and an
 * optional word "version"): a digit followed by digits, letters, '.', '-', '_',
 * '+' or '~'. Writes "" if there is none.
 */
static void read_version(const unsigned char *cursor, const unsigned char *end, char *out, size_t out_size)
{
    out[0] = '\0';
    while (cursor < end && *cursor == ' ') {
        cursor++;
    }
    if ((size_t)(end - cursor) > 8 && strncasecmp((const char *)cursor, "version ", 8) == 0) {
        cursor += 8;
    }
    if (cursor >= end || !is_digit(*cursor)) {
        return;
    }
    const unsigned char *start = cursor;
    while (cursor < end) {
        unsigned char c = *cursor;
        bool allowed = is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' ||
                       c == '_' || c == '+' || c == '~';
        if (!allowed) {
            break;
        }
        cursor++;
    }
    /* "3.0.5." at the end of a sentence: drop trailing punctuation. */
    while (cursor > start && (cursor[-1] == '.' || cursor[-1] == '-')) {
        cursor--;
    }
    copy_text(out, out_size, start, (size_t)(cursor - start));
}

/*
 * Split "name/1.2.3 (rest)" into product "name", version "1.2.3" and info
 * "rest" (outer parentheses removed). Without '/', the whole first word is the
 * product. Used for HTTP Server headers.
 */
static void split_product_token(const unsigned char *text, size_t length, service_info *out)
{
    while (length > 0 && is_space(*text)) {
        text++;
        length--;
    }
    size_t word = 0;
    while (word < length && text[word] != ' ') {
        word++;
    }
    size_t slash = 0;
    while (slash < word && text[slash] != '/') {
        slash++;
    }
    copy_text(out->product, sizeof out->product, text, slash);
    if (slash + 1 < word) {
        copy_text(out->version, sizeof out->version, text + slash + 1, word - slash - 1);
    }
    const unsigned char *rest = text + word;
    size_t rest_length = length - word;
    while (rest_length > 0 && is_space(*rest)) {
        rest++;
        rest_length--;
    }
    while (rest_length > 0 && is_space(rest[rest_length - 1])) {
        rest_length--;
    }
    if (rest_length >= 2 && rest[0] == '(' && rest[rest_length - 1] == ')') {
        rest++;
        rest_length -= 2;
    }
    copy_text(out->info, sizeof out->info, rest, rest_length);
}

/* Find "Name: value" in an HTTP-style header block; *value_length gets the value's length. */
static const unsigned char *find_header(const unsigned char *data, size_t length, const char *name,
                                        size_t *value_length)
{
    size_t name_length = strlen(name);
    size_t position = line_length(data, length); /* skip the status line */
    while (position < length) {
        /* Step over the line break (CRLF, or a bare LF). */
        if (data[position] == '\r') {
            position++;
        }
        if (position < length && data[position] == '\n') {
            position++;
        }
        const unsigned char *line = data + position;
        size_t line_end = line_length(line, length - position);
        if (line_end == 0) {
            return NULL; /* empty line: end of the headers */
        }
        if (line_end > name_length && line[name_length] == ':' &&
            strncasecmp((const char *)line, name, name_length) == 0) {
            *value_length = line_end - name_length - 1;
            return line + name_length + 1;
        }
        position += line_end;
    }
    return NULL;
}

/* ---- TLS --------------------------------------------------------------------- */

static const char *tls_version_name(unsigned version)
{
    switch (version) {
    case 0x0300:
        return "SSL 3.0";
    case 0x0301:
        return "TLS 1.0";
    case 0x0302:
        return "TLS 1.1";
    case 0x0303:
        return "TLS 1.2";
    case 0x0304:
        return "TLS 1.3";
    default:
        return "";
    }
}

/* Names of the cipher suites Janus offers (the server must pick one of them). */
static const char *tls_cipher_name(unsigned suite)
{
    switch (suite) {
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256";
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384";
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xc02b:
        return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case 0xc02c:
        return "ECDHE-ECDSA-AES256-GCM-SHA384";
    case 0xc02f:
        return "ECDHE-RSA-AES128-GCM-SHA256";
    case 0xc030:
        return "ECDHE-RSA-AES256-GCM-SHA384";
    case 0xcca8:
        return "ECDHE-RSA-CHACHA20-POLY1305";
    case 0xcca9:
        return "ECDHE-ECDSA-CHACHA20-POLY1305";
    case 0xc013:
        return "ECDHE-RSA-AES128-SHA";
    case 0xc014:
        return "ECDHE-RSA-AES256-SHA";
    case 0x009c:
        return "AES128-GCM-SHA256";
    case 0x009d:
        return "AES256-GCM-SHA384";
    case 0x002f:
        return "AES128-SHA";
    case 0x0035:
        return "AES256-SHA";
    case 0x000a:
        return "DES-CBC3-SHA";
    default:
        return "";
    }
}

static const char *tls_alert_name(unsigned description)
{
    switch (description) {
    case 10:
        return "unexpected_message";
    case 40:
        return "handshake_failure";
    case 47:
        return "illegal_parameter";
    case 50:
        return "decode_error";
    case 70:
        return "protocol_version";
    case 71:
        return "insufficient_security";
    case 80:
        return "internal_error";
    case 112:
        return "unrecognized_name";
    default:
        return "other";
    }
}

static unsigned read_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static size_t read_u24(const unsigned char *p)
{
    return (size_t)p[0] << 16 | (size_t)p[1] << 8 | p[2];
}

/* Longest handshake stream Janus reassembles (the reply buffer is not larger). */
#define TLS_STREAM_MAX 16384

/*
 * A TLS server's first flight can spread its handshake messages over several
 * records, and one message over several records. Copy the payloads of the
 * leading handshake records (type 22) into one stream. *ended is set when a
 * record of another type follows, so nothing more will be added.
 */
static size_t tls_handshake_stream(const unsigned char *data, size_t length, unsigned char *stream,
                                   size_t stream_size, bool *ended)
{
    size_t position = 0;
    size_t used = 0;
    *ended = false;
    while (position + 5 <= length) {
        if (data[position] != 0x16 || data[position + 1] != 0x03) {
            *ended = true;
            break;
        }
        size_t record_length = read_u16(data + position + 3);
        size_t present = length - position - 5;
        size_t take = present < record_length ? present : record_length;
        if (take > stream_size - used) {
            take = stream_size - used;
        }
        memcpy(stream + used, data + position + 5, take);
        used += take;
        if (take < record_length) {
            break; /* the rest of this record has not arrived (or does not fit) */
        }
        position += 5 + record_length;
    }
    return used;
}

/*
 * ServerHello body (after the 4-byte message header): legacy_version(2)
 * random(32) session_id(1+n) cipher_suite(2) compression(1) extensions(2+n).
 * TLS 1.3 servers put 0x0303 in the legacy field and the real version into
 * the supported_versions extension (43). Returns false if too short.
 */
static bool parse_server_hello(const unsigned char *body, size_t length, unsigned *version, unsigned *suite)
{
    *version = 0;
    *suite = 0;
    if (length < 35) {
        return false;
    }
    *version = read_u16(body);
    size_t offset = 35 + body[34]; /* skip the session id */
    if (offset + 3 > length) {
        return true;
    }
    *suite = read_u16(body + offset);
    offset += 3;
    if (offset + 2 > length) {
        return true;
    }
    size_t extensions_end = offset + 2 + read_u16(body + offset);
    if (extensions_end > length) {
        extensions_end = length;
    }
    offset += 2;
    while (offset + 4 <= extensions_end) {
        unsigned type = read_u16(body + offset);
        size_t extension_length = read_u16(body + offset + 2);
        offset += 4;
        if (offset + extension_length > extensions_end) {
            break;
        }
        if (type == 0x002b && extension_length == 2) {
            *version = read_u16(body + offset);
        }
        offset += extension_length;
    }
    return true;
}

bool tls_reply_complete(const unsigned char *data, size_t length)
{
    if (length >= 1 && data[0] == 0x15) {
        return true; /* an alert ends the conversation */
    }
    unsigned char stream[TLS_STREAM_MAX];
    bool ended = false;
    size_t used = tls_handshake_stream(data, length, stream, sizeof stream, &ended);
    if (used >= 1 && stream[0] != 0x02) {
        return true; /* not a ServerHello: nothing worth waiting for */
    }
    if (used < 4) {
        return ended;
    }
    size_t hello_end = 4 + read_u24(stream + 1);
    if (used < hello_end) {
        return ended;
    }
    unsigned version = 0;
    unsigned suite = 0;
    if (!parse_server_hello(stream + 4, hello_end - 4, &version, &suite) || version >= 0x0304) {
        return true; /* TLS 1.3 encrypts the certificate: the ServerHello is all there is to read */
    }
    /* TLS 1.2 and older: the Certificate message (11) follows in clear text. */
    size_t offset = hello_end;
    while (offset + 4 <= used) {
        unsigned type = stream[offset];
        size_t message_length = read_u24(stream + offset + 1);
        if (type == 11) {
            if (offset + 10 > used) {
                return ended;
            }
            size_t first = read_u24(stream + offset + 7);
            return ended || used >= offset + 10 + first;
        }
        if (type == 14) {
            return true; /* ServerHelloDone without a certificate */
        }
        offset += 4 + message_length;
    }
    return ended;
}

/*
 * A TLS record starts with: content type (22 handshake, 21 alert), version
 * 3.x, and a 2-byte length. The ServerHello tells the protocol version and
 * cipher suite the server chose; in TLS 1.2 and older the next message is the
 * server's certificate chain, readable without finishing the handshake.
 */
static bool identify_tls(const unsigned char *data, size_t length, service_info *out)
{
    if (length < 7 || data[1] != 0x03 || data[2] > 0x04) {
        return false;
    }
    size_t record_length = read_u16(data + 3);

    if (data[0] == 0x15) { /* alert: 2 bytes, level and description */
        if (record_length != 2 || (data[5] != 1 && data[5] != 2)) {
            return false;
        }
        set_text(out->service, sizeof out->service, "tls");
        set_text(out->info, sizeof out->info, "alert:");
        append_text(out->info, sizeof out->info, " ", tls_alert_name(data[6]));
        return true;
    }
    if (data[0] != 0x16 || data[5] != 0x02 || record_length < 4) {
        return false; /* not a handshake record carrying a ServerHello */
    }
    set_text(out->service, sizeof out->service, "tls");

    unsigned char stream[TLS_STREAM_MAX];
    bool ended = false;
    size_t used = tls_handshake_stream(data, length, stream, sizeof stream, &ended);
    if (used < 4) {
        return true; /* truncated, but clearly a ServerHello */
    }
    size_t hello_end = 4 + read_u24(stream + 1);
    size_t hello_available = (used < hello_end ? used : hello_end) - 4;
    unsigned version = 0;
    unsigned suite = 0;
    if (!parse_server_hello(stream + 4, hello_available, &version, &suite)) {
        return true; /* truncated, but clearly a ServerHello */
    }
    append_text(out->info, sizeof out->info, ", ", tls_version_name(version));
    append_text(out->info, sizeof out->info, ", ", tls_cipher_name(suite));

    /* Look for the Certificate message and parse the first (the server's own) certificate. */
    size_t offset = hello_end;
    while (offset + 4 <= used) {
        unsigned type = stream[offset];
        size_t message_length = read_u24(stream + offset + 1);
        if (type == 11 && offset + 10 <= used) {
            size_t first = read_u24(stream + offset + 7);
            size_t available = used - offset - 10;
            parse_certificate(stream + offset + 10, first < available ? first : available, &out->certificate);
            break;
        }
        offset += 4 + message_length;
    }
    return true;
}

/* A tiny append-only writer, so the ClientHello can be assembled field by field. */
typedef struct {
    unsigned char *data;
    size_t size;
    size_t used;
    bool overflow;
} byte_writer;

static void put_bytes(byte_writer *writer, const void *bytes, size_t count)
{
    if (writer->overflow || count > writer->size - writer->used) {
        writer->overflow = true;
        return;
    }
    memcpy(writer->data + writer->used, bytes, count);
    writer->used += count;
}

static void put_u8(byte_writer *writer, unsigned value)
{
    unsigned char byte = (unsigned char)value;
    put_bytes(writer, &byte, 1);
}

static void put_u16(byte_writer *writer, size_t value)
{
    unsigned char bytes[2] = {(unsigned char)(value >> 8), (unsigned char)value};
    put_bytes(writer, bytes, 2);
}

/* Write a length placeholder now, fill it in once the content is known. */
static void patch_length(byte_writer *writer, size_t at, size_t width)
{
    if (writer->overflow) {
        return;
    }
    size_t value = writer->used - at - width;
    for (size_t i = 0; i < width; i++) {
        writer->data[at + i] = (unsigned char)(value >> (8 * (width - 1 - i)));
    }
}

/* SNI must be a DNS name: letters, digits, '-' and '.', not an IP address literal. */
static bool valid_server_name(const char *name)
{
    size_t length = name != NULL ? strlen(name) : 0;
    if (length == 0 || length > 253) {
        return false;
    }
    bool has_letter = false;
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        has_letter |= letter;
        if (!letter && !is_digit((unsigned char)c) && c != '-' && c != '.') {
            return false;
        }
    }
    return has_letter;
}

size_t tls_client_hello(unsigned char *buffer, size_t buffer_size, const char *server_name, bool tls12_only)
{
    /* RFC 7748 example public key: any 32 bytes work as an X25519 share for a probe. */
    static const unsigned char key_share[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    static const unsigned char tls13_suites[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
    static const unsigned char suites[] = {
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, /* ECDHE + AEAD */
        0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, /* older */
    };
    static const unsigned char common_extensions[] = {
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, /* groups: x25519, P-256, P-384 */
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,                                     /* EC point formats: uncompressed */
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, /* signature algorithms */
        0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
    };
    static const unsigned char tls13_extensions[] = {
        0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, /* supported versions: 1.3, 1.2 */
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,                   /* PSK modes (expected by TLS 1.3 servers) */
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, /* key share: x25519, 32 bytes follow */
    };

    byte_writer w = {buffer, buffer_size, 0, false};
    put_u8(&w, 0x16); /* handshake record */
    put_u16(&w, 0x0301); /* record version TLS 1.0, as browsers send for compatibility */
    size_t record_at = w.used;
    put_u16(&w, 0);
    put_u8(&w, 0x01); /* ClientHello */
    size_t hello_at = w.used;
    put_u8(&w, 0); /* 3-byte length, filled in at the end */
    put_u16(&w, 0);
    put_u16(&w, 0x0303); /* legacy version TLS 1.2 */
    for (unsigned i = 0; i < 32; i++) {
        put_u8(&w, 0x4a + i); /* "random": fixed, this is only a probe */
    }
    put_u8(&w, 0); /* no session id */
    put_u16(&w, (tls12_only ? 0 : sizeof tls13_suites) + sizeof suites);
    if (!tls12_only) {
        put_bytes(&w, tls13_suites, sizeof tls13_suites);
    }
    put_bytes(&w, suites, sizeof suites);
    put_u8(&w, 1); /* one compression method: */
    put_u8(&w, 0); /* none */
    size_t extensions_at = w.used;
    put_u16(&w, 0);
    if (valid_server_name(server_name)) {
        size_t name_length = strlen(server_name);
        put_u16(&w, 0x0000);          /* server_name */
        put_u16(&w, name_length + 5); /* extension length */
        put_u16(&w, name_length + 3); /* list length */
        put_u8(&w, 0);                /* type: host name */
        put_u16(&w, name_length);
        put_bytes(&w, server_name, name_length);
    }
    put_bytes(&w, common_extensions, sizeof common_extensions);
    if (!tls12_only) {
        put_bytes(&w, tls13_extensions, sizeof tls13_extensions);
        put_bytes(&w, key_share, sizeof key_share);
    }
    patch_length(&w, extensions_at, 2);
    patch_length(&w, hello_at, 3);
    patch_length(&w, record_at, 2);
    return w.overflow ? 0 : w.used;
}

/* ---- X.509 certificates (DER) ------------------------------------------------------ */

/*
 * DER encodes everything as tag, length, value. A der_span is a window into
 * the certificate; der_next() takes one element off its front and refuses
 * any length that points outside the window, so a hostile certificate can
 * never make the parser read past the bytes received.
 */
typedef struct {
    const unsigned char *data;
    size_t length;
} der_span;

static bool der_next(der_span *in, unsigned char *tag, der_span *value, der_span *whole)
{
    if (in->length < 2 || (in->data[0] & 0x1f) == 0x1f) {
        return false; /* too short, or a multi-byte tag (never used in certificates) */
    }
    size_t length = in->data[1];
    size_t header = 2;
    if (length & 0x80) {
        size_t count = length & 0x7f;
        if (count == 0 || count > 3 || in->length < 2 + count) {
            return false;
        }
        length = 0;
        for (size_t i = 0; i < count; i++) {
            length = length << 8 | in->data[2 + i];
        }
        header += count;
    }
    if (length > in->length - header) {
        return false;
    }
    *tag = in->data[0];
    value->data = in->data + header;
    value->length = length;
    if (whole != NULL) {
        whole->data = in->data;
        whole->length = header + length;
    }
    in->data += header + length;
    in->length -= header + length;
    return true;
}

static bool der_expect(der_span *in, unsigned char wanted, der_span *value)
{
    unsigned char tag = 0;
    return der_next(in, &tag, value, NULL) && tag == wanted;
}

static bool oid_is(der_span oid, const unsigned char *expected, size_t expected_length)
{
    return oid.length == expected_length && memcmp(oid.data, expected, expected_length) == 0;
}

/* Directory string types: UTF8String, PrintableString, T61String, IA5String, BMPString. */
static bool is_string_tag(unsigned char tag)
{
    return tag == 0x0c || tag == 0x13 || tag == 0x14 || tag == 0x16 || tag == 0x1e;
}

/* Value of the attribute 2.5.4.<attribute> (3 = CN, 10 = O, 11 = OU) in a Name, or false. */
static bool name_attribute(der_span name, unsigned char attribute, char *out, size_t out_size)
{
    der_span set;
    while (der_expect(&name, 0x31, &set)) {
        der_span pair;
        while (der_expect(&set, 0x30, &pair)) {
            der_span oid;
            der_span value;
            unsigned char tag = 0;
            const unsigned char expected[3] = {0x55, 0x04, attribute};
            if (der_expect(&pair, 0x06, &oid) && der_next(&pair, &tag, &value, NULL) && is_string_tag(tag) &&
                oid_is(oid, expected, sizeof expected)) {
                copy_text(out, out_size, value.data, value.length);
                return out[0] != '\0';
            }
        }
    }
    return false;
}

static void name_label(der_span name, char *out, size_t out_size)
{
    if (!name_attribute(name, 3, out, out_size) && !name_attribute(name, 10, out, out_size)) {
        name_attribute(name, 11, out, out_size);
    }
}

/* UTCTime "YYMMDDHHMMSSZ" or GeneralizedTime "YYYYMMDDHHMMSSZ" -> "YYYY-MM-DDTHH:MM:SSZ". */
static bool parse_time(unsigned char tag, der_span value, char *out, size_t out_size)
{
    size_t digits = tag == 0x17 ? 12 : tag == 0x18 ? 14 : 0;
    if (digits == 0 || value.length != digits + 1 || value.data[digits] != 'Z' || out_size < CERT_TIME_SIZE) {
        return false;
    }
    for (size_t i = 0; i < digits; i++) {
        if (!is_digit(value.data[i])) {
            return false;
        }
    }
    const unsigned char *t = value.data;
    char year[5];
    if (tag == 0x17) {
        /* RFC 5280: two-digit years 50-99 are 19xx, 00-49 are 20xx. */
        bool old = t[0] >= '5';
        year[0] = old ? '1' : '2';
        year[1] = old ? '9' : '0';
        year[2] = (char)t[0];
        year[3] = (char)t[1];
        t += 2;
    } else {
        memcpy(year, t, 4);
        t += 4;
    }
    year[4] = '\0';
    snprintf(out, out_size, "%s-%c%c-%c%cT%c%c:%c%c:%c%cZ", year, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
             t[8], t[9]);
    return true;
}

/* "RSA 2048", "EC P-256", "Ed25519" from SubjectPublicKeyInfo. */
static void describe_key(der_span info, char *out, size_t out_size)
{
    static const unsigned char rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    static const unsigned char ec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    static const unsigned char p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const unsigned char p384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};
    static const unsigned char p521[] = {0x2b, 0x81, 0x04, 0x00, 0x23};
    static const unsigned char ed25519[] = {0x2b, 0x65, 0x70};
    static const unsigned char ed448[] = {0x2b, 0x65, 0x71};

    der_span algorithm;
    der_span oid;
    der_span bits;
    if (!der_expect(&info, 0x30, &algorithm) || !der_expect(&algorithm, 0x06, &oid) ||
        !der_expect(&info, 0x03, &bits)) {
        return;
    }
    if (oid_is(oid, rsa, sizeof rsa)) {
        /* BIT STRING: one "unused bits" byte, then SEQUENCE { modulus INTEGER, exponent INTEGER }. */
        der_span key = {bits.data + 1, bits.length > 0 ? bits.length - 1 : 0};
        der_span sequence;
        der_span modulus;
        if (bits.length < 1 || !der_expect(&key, 0x30, &sequence) || !der_expect(&sequence, 0x02, &modulus)) {
            set_text(out, out_size, "RSA");
            return;
        }
        while (modulus.length > 0 && modulus.data[0] == 0) {
            modulus.data++;
            modulus.length--;
        }
        size_t key_bits = modulus.length * 8;
        for (unsigned char top = modulus.length ? modulus.data[0] : 0x80; key_bits > 0 && !(top & 0x80); top <<= 1) {
            key_bits--;
        }
        snprintf(out, out_size, "RSA %zu", key_bits);
    } else if (oid_is(oid, ec, sizeof ec)) {
        der_span curve;
        const char *name = "";
        if (der_expect(&algorithm, 0x06, &curve)) {
            name = oid_is(curve, p256, sizeof p256)   ? " P-256"
                   : oid_is(curve, p384, sizeof p384) ? " P-384"
                   : oid_is(curve, p521, sizeof p521) ? " P-521"
                                                      : "";
        }
        snprintf(out, out_size, "EC%s", name);
    } else if (oid_is(oid, ed25519, sizeof ed25519)) {
        set_text(out, out_size, "Ed25519");
    } else if (oid_is(oid, ed448, sizeof ed448)) {
        set_text(out, out_size, "Ed448");
    }
}

/* subjectAltName: dNSName [2] and iPAddress [7] entries. */
static void read_alt_names(der_span value, tls_certificate *out)
{
    der_span names;
    if (!der_expect(&value, 0x30, &names)) {
        return;
    }
    unsigned char tag = 0;
    der_span name;
    while (out->name_count < CERT_MAX_NAMES && der_next(&names, &tag, &name, NULL)) {
        char *slot = out->names[out->name_count];
        if (tag == 0x82) {
            copy_text(slot, CERT_TEXT_SIZE, name.data, name.length);
        } else if (tag == 0x87 && (name.length == 4 || name.length == 16)) {
            inet_ntop(name.length == 4 ? AF_INET : AF_INET6, name.data, slot, CERT_TEXT_SIZE);
        } else {
            continue; /* e-mail addresses, URIs, ... */
        }
        if (slot[0] != '\0') {
            out->name_count++;
        }
    }
}

bool parse_certificate(const unsigned char *der, size_t length, tls_certificate *out)
{
    static const unsigned char alt_names_oid[] = {0x55, 0x1d, 0x11};
    memset(out, 0, sizeof *out);
    der_span input = {der, length};
    der_span certificate;
    der_span tbs;
    if (!der_expect(&input, 0x30, &certificate) || !der_expect(&certificate, 0x30, &tbs)) {
        return false;
    }
    unsigned char tag = 0;
    der_span value;
    if (tbs.length > 0 && tbs.data[0] == 0xa0 && !der_next(&tbs, &tag, &value, NULL)) {
        return false; /* [0] version */
    }
    der_span issuer;
    der_span issuer_whole;
    der_span validity;
    der_span subject;
    der_span subject_whole;
    der_span key_info;
    if (!der_expect(&tbs, 0x02, &value) || /* serial number */
        !der_expect(&tbs, 0x30, &value) || /* signature algorithm */
        !der_next(&tbs, &tag, &issuer, &issuer_whole) || tag != 0x30 || !der_expect(&tbs, 0x30, &validity) ||
        !der_next(&tbs, &tag, &subject, &subject_whole) || tag != 0x30 || !der_expect(&tbs, 0x30, &key_info)) {
        return false;
    }
    der_span time;
    if (!der_next(&validity, &tag, &time, NULL) || !parse_time(tag, time, out->not_before, sizeof out->not_before) ||
        !der_next(&validity, &tag, &time, NULL) || !parse_time(tag, time, out->not_after, sizeof out->not_after)) {
        return false;
    }
    name_label(subject, out->subject, sizeof out->subject);
    name_label(issuer, out->issuer, sizeof out->issuer);
    out->self_signed = issuer_whole.length == subject_whole.length &&
                       memcmp(issuer_whole.data, subject_whole.data, issuer_whole.length) == 0;
    describe_key(key_info, out->key, sizeof out->key);

    /* Optional fields; extensions are [3] { SEQUENCE OF { OID, critical BOOLEAN?, OCTET STRING } }. */
    while (der_next(&tbs, &tag, &value, NULL)) {
        der_span extensions;
        if (tag != 0xa3 || !der_expect(&value, 0x30, &extensions)) {
            continue;
        }
        der_span extension;
        while (der_expect(&extensions, 0x30, &extension)) {
            der_span oid;
            der_span content;
            if (!der_expect(&extension, 0x06, &oid)) {
                continue;
            }
            if (extension.length > 0 && extension.data[0] == 0x01 && !der_next(&extension, &tag, &content, NULL)) {
                continue;
            }
            if (der_expect(&extension, 0x04, &content) && oid_is(oid, alt_names_oid, sizeof alt_names_oid)) {
                read_alt_names(content, out);
            }
        }
    }
    out->present = true;
    return true;
}

bool certificate_expired(const tls_certificate *certificate, const char *now)
{
    return certificate->present && certificate->not_after[0] != '\0' && now[0] != '\0' &&
           strcmp(certificate->not_after, now) < 0;
}

bool certificate_not_yet_valid(const tls_certificate *certificate, const char *now)
{
    return certificate->present && certificate->not_before[0] != '\0' && now[0] != '\0' &&
           strcmp(now, certificate->not_before) < 0;
}

size_t pgsql_ssl_request(unsigned char *buffer, size_t buffer_size)
{
    /* Length 8, then the magic request code 80877103 (0x04d2162f). */
    static const unsigned char request[8] = {0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f};
    if (buffer_size < sizeof request) {
        return 0;
    }
    memcpy(buffer, request, sizeof request);
    return sizeof request;
}

/* ---- binary greetings ------------------------------------------------------------ */

/*
 * MySQL and MariaDB speak first: a packet with a 3-byte little-endian length,
 * sequence number 0, protocol version 10 and a NUL-terminated server version.
 * A server that refuses the client sends an error packet (0xff) instead.
 */
static bool identify_mysql(const unsigned char *data, size_t length, service_info *out)
{
    if (length < 7 || data[3] != 0) {
        return false;
    }
    size_t packet_length = (size_t)data[0] | (size_t)data[1] << 8 | (size_t)data[2] << 16;
    if (packet_length < 3 || packet_length > 1024) {
        return false;
    }
    size_t end = 4 + packet_length < length ? 4 + packet_length : length;

    if (data[4] == 0xff) {
        /* Error packet: code (2 bytes, little endian) and a message. */
        unsigned code = (unsigned)data[5] | (unsigned)data[6] << 8;
        const unsigned char *message = data + 7;
        size_t message_length = end - 7;
        bool mentions = find_text(message, message_length, "MySQL", false) != NULL ||
                        find_text(message, message_length, "MariaDB", false) != NULL;
        if (!mentions && code != 1040 && code != 1129 && code != 1130) {
            return false;
        }
        set_text(out->service, sizeof out->service, "mysql");
        copy_text(out->info, sizeof out->info, message, message_length);
        return true;
    }
    if (data[4] != 0x0a) {
        return false;
    }
    const unsigned char *text = data + 5;
    size_t text_end = 0;
    while (5 + text_end < end && text[text_end] != '\0') {
        text_end++;
    }
    if (5 + text_end >= end || text_end == 0 || !is_digit(text[0])) {
        return false; /* no terminating NUL, or not a version string */
    }

    bool mariadb = find_text(text, text_end, "MariaDB", false) != NULL;
    set_text(out->service, sizeof out->service, "mysql");
    set_text(out->product, sizeof out->product, mariadb ? "MariaDB" : "MySQL");
    /* MariaDB before 11 prefixes "5.5.5-" so old clients accept it. */
    const unsigned char *cursor = text;
    if (mariadb && text_end > 6 && memcmp(text, "5.5.5-", 6) == 0) {
        cursor += 6;
    }
    const unsigned char *text_stop = text + text_end;
    const unsigned char *version_end = cursor;
    while (version_end < text_stop && (is_digit(*version_end) || *version_end == '.')) {
        version_end++;
    }
    copy_text(out->version, sizeof out->version, cursor, (size_t)(version_end - cursor));
    /* The rest is distribution detail, e.g. "-0ubuntu0.22.04.1" or "-MariaDB-0+deb12u1". */
    cursor = version_end;
    if (cursor < text_stop && *cursor == '-') {
        cursor++;
    }
    if (mariadb && (size_t)(text_stop - cursor) >= 7 && memcmp(cursor, "MariaDB", 7) == 0) {
        cursor += 7;
        if (cursor < text_stop && *cursor == '-') {
            cursor++;
        }
    }
    copy_text(out->info, sizeof out->info, cursor, (size_t)(text_stop - cursor));
    return true;
}

/* ---- text greetings --------------------------------------------------------------- */

/* "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" (RFC 4253, section 4.2). */
static bool identify_ssh(const unsigned char *data, size_t length, service_info *out)
{
    if (!has_prefix(data, length, "SSH-")) {
        return false;
    }
    size_t line = line_length(data, length);
    const unsigned char *protocol = data + 4;
    const unsigned char *end = data + line;
    const unsigned char *dash = protocol;
    while (dash < end && *dash != '-') {
        dash++;
    }
    if (dash == end || dash == protocol) {
        return false;
    }
    const unsigned char *software = dash + 1;
    const unsigned char *space = software;
    while (space < end && *space != ' ') {
        space++;
    }
    const unsigned char *underscore = software;
    while (underscore < space && *underscore != '_') {
        underscore++;
    }

    set_text(out->service, sizeof out->service, "ssh");
    copy_text(out->product, sizeof out->product, software, (size_t)(underscore - software));
    if (underscore < space) {
        copy_text(out->version, sizeof out->version, underscore + 1, (size_t)(space - underscore - 1));
    }
    /* "OpenSSH_for_Windows_8.1" */
    if (strcmp(out->product, "OpenSSH") == 0 && strncmp(out->version, "for_Windows_", 12) == 0) {
        set_text(out->product, sizeof out->product, "OpenSSH for Windows");
        memmove(out->version, out->version + 12, strlen(out->version + 12) + 1);
    } else if (strcmp(out->product, "dropbear") == 0) {
        set_text(out->product, sizeof out->product, "Dropbear");
    }
    copy_text(out->info, sizeof out->info, space, (size_t)(end - space));
    if ((size_t)(dash - protocol) != 3 || memcmp(protocol, "2.0", 3) != 0) {
        char protocol_text[24] = "protocol ";
        char version_text[12];
        copy_text(version_text, sizeof version_text, protocol, (size_t)(dash - protocol));
        append_text(protocol_text, sizeof protocol_text, "", version_text);
        append_text(out->info, sizeof out->info, ", ", protocol_text);
    }
    return true;
}

/* "HTTP/1.1 200 OK" plus headers; the Server header names the software. */
static bool identify_http(const unsigned char *data, size_t length, service_info *out)
{
    const char *service = NULL;
    if (has_prefix(data, length, "HTTP/1.") || has_prefix(data, length, "HTTP/2")) {
        service = "http";
    } else if (has_prefix(data, length, "RTSP/1.")) {
        service = "rtsp"; /* IP cameras: the same message format as HTTP */
    } else {
        return false;
    }
    set_text(out->service, sizeof out->service, service);
    size_t value_length = 0;
    const unsigned char *server = find_header(data, length, "Server", &value_length);
    if (server != NULL) {
        split_product_token(server, value_length, out);
    }
    return true;
}

/* Software that names itself in FTP, SMTP, POP3 and IMAP greetings. */
typedef struct {
    const char *marker;  /* text to look for, case-sensitive */
    const char *product; /* what to report */
} product_marker;

static const product_marker greeting_products[] = {
    {"vsFTPd", "vsftpd"},
    {"ProFTPD", "ProFTPD"},
    {"Pure-FTPd", "Pure-FTPd"},
    {"FileZilla Server", "FileZilla Server"},
    {"Microsoft FTP Service", "Microsoft FTP Service"},
    {"Serv-U", "Serv-U"},
    {"Postfix", "Postfix"},
    {"Exim", "Exim"},
    {"Sendmail", "Sendmail"},
    {"OpenSMTPD", "OpenSMTPD"},
    {"Microsoft ESMTP MAIL Service", "Microsoft ESMTP"},
    {"Dovecot", "Dovecot"},
    {"Cyrus", "Cyrus"},
    {"Courier", "Courier"},
};

static void find_greeting_product(const unsigned char *line, size_t length, service_info *out)
{
    for (size_t i = 0; i < sizeof greeting_products / sizeof greeting_products[0]; i++) {
        const unsigned char *found = find_text(line, length, greeting_products[i].marker, false);
        if (found != NULL) {
            set_text(out->product, sizeof out->product, greeting_products[i].product);
            const unsigned char *after = found + strlen(greeting_products[i].marker);
            read_version(after, line + length, out->version, sizeof out->version);
            return;
        }
    }
}

/* FTP and SMTP both greet with "220"; POP3 with "+OK"; IMAP with "* OK". */
static bool identify_mail_or_ftp(const unsigned char *data, size_t length, service_info *out)
{
    size_t line = line_length(data, length);
    const char *service = NULL;
    if (has_prefix(data, line, "220")) {
        if (find_text(data, line, "FTP", true) != NULL) {
            service = "ftp";
        } else if (find_text(data, line, "SMTP", true) != NULL) {
            service = "smtp";
        } else if (find_text(data, line, "FileZilla", false) != NULL) {
            service = "ftp";
        }
    } else if (has_prefix(data, line, "+OK")) {
        service = "pop3";
    } else if (has_prefix(data, line, "* OK") || has_prefix(data, line, "* PREAUTH")) {
        service = "imap";
    }
    if (service == NULL) {
        return false;
    }
    set_text(out->service, sizeof out->service, service);
    find_greeting_product(data, line, out);
    return true;
}

/* "RFB 003.008\n": a VNC server announces its protocol version. */
static bool identify_vnc(const unsigned char *data, size_t length, service_info *out)
{
    if (length < 12 || !has_prefix(data, length, "RFB ") || data[7] != '.' || data[11] != '\n') {
        return false;
    }
    for (size_t i = 4; i < 11; i++) {
        if (i != 7 && !is_digit(data[i])) {
            return false;
        }
    }
    int major = (data[4] - '0') * 100 + (data[5] - '0') * 10 + (data[6] - '0');
    int minor = (data[8] - '0') * 100 + (data[9] - '0') * 10 + (data[10] - '0');
    set_text(out->service, sizeof out->service, "vnc");
    snprintf(out->info, sizeof out->info, "protocol %d.%d", major, minor);
    return true;
}

/* Replies that only make sense as an answer to Janus' HEAD request. */
static bool identify_probe_errors(const unsigned char *data, size_t length, service_info *out)
{
    /* Redis answers an unknown command (HEAD) with "-ERR unknown command ...". */
    if (has_prefix(data, length, "-ERR unknown command") || has_prefix(data, length, "-NOAUTH") ||
        has_prefix(data, length, "-DENIED Redis")) {
        set_text(out->service, sizeof out->service, "redis");
        set_text(out->product, sizeof out->product, "Redis");
        if (has_prefix(data, length, "-NOAUTH")) {
            set_text(out->info, sizeof out->info, "authentication required");
        } else if (has_prefix(data, length, "-DENIED")) {
            set_text(out->info, sizeof out->info, "protected mode");
        }
        return true;
    }
    /* memcached answers every line it does not understand with "ERROR". */
    if (length >= 7 && length % 7 == 0) {
        bool all_errors = true;
        for (size_t i = 0; i < length; i += 7) {
            all_errors &= memcmp(data + i, "ERROR\r\n", 7) == 0;
        }
        if (all_errors) {
            set_text(out->service, sizeof out->service, "memcached");
            return true;
        }
    }
    /* RabbitMQ and other AMQP brokers answer a wrong header with the one they speak. */
    if (length == 8 && has_prefix(data, length, "AMQP") && data[5] < 10 && data[6] < 10 && data[7] < 10) {
        set_text(out->service, sizeof out->service, "amqp");
        snprintf(out->info, sizeof out->info, "protocol %d-%d-%d", data[5], data[6], data[7]);
        return true;
    }
    return false;
}

bool identify_tcp_reply(probe_kind probe, const unsigned char *data, size_t length, service_info *out)
{
    memset(out, 0, sizeof *out);
    if (length == 0) {
        return false;
    }
    if (probe == PROBE_PGSQL && length == 1 && (data[0] == 'S' || data[0] == 'N')) {
        set_text(out->service, sizeof out->service, "postgresql");
        set_text(out->product, sizeof out->product, "PostgreSQL");
        set_text(out->info, sizeof out->info, data[0] == 'S' ? "TLS supported" : "TLS not offered");
        return true;
    }
    /* Telnet servers usually start with option negotiation: IAC (255) WILL/WONT/DO/DONT. */
    if (length >= 3 && data[0] == 0xff && data[1] >= 0xfb && data[1] <= 0xfe) {
        set_text(out->service, sizeof out->service, "telnet");
        return true;
    }
    bool found = identify_tls(data, length, out) || identify_mysql(data, length, out) ||
                 identify_ssh(data, length, out) || identify_http(data, length, out) ||
                 identify_vnc(data, length, out) || identify_mail_or_ftp(data, length, out) ||
                 identify_probe_errors(data, length, out);
    if (!found) {
        memset(out, 0, sizeof *out); /* a matcher may have started filling in before it gave up */
    }
    return found;
}

/* ---- UDP replies ----------------------------------------------------------------- */

/* Janus' DNS-style probes use ID 0x1234; a reply has the QR bit set. */
static bool is_dns_reply(const unsigned char *data, size_t length)
{
    return length >= 12 && data[0] == 0x12 && data[1] == 0x34 && (data[2] & 0x80) != 0;
}

static bool identify_dns(const unsigned char *data, size_t length, service_info *out)
{
    if (!is_dns_reply(data, length)) {
        return false;
    }
    static const char *const rcodes[] = {"", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    set_text(out->service, sizeof out->service, "domain");
    if (data[3] & 0x80) {
        append_text(out->info, sizeof out->info, ", ", "recursion available");
    }
    unsigned rcode = data[3] & 0x0f;
    if (rcode >= 1 && rcode <= 5) {
        append_text(out->info, sizeof out->info, ", ", rcodes[rcode]);
    }
    return true;
}

/*
 * Decode a (possibly compressed) DNS name at *offset into "a.b.c". On return
 * *offset points behind the name in the original position. Compression
 * pointers may only jump backwards, so a hostile packet cannot loop forever.
 */
static bool read_dns_name(const unsigned char *data, size_t length, size_t *offset, char *out, size_t out_size)
{
    size_t position = *offset;
    size_t resume = 0; /* where parsing continues after the first jump; 0 = no jump yet */
    size_t used = 0;
    out[0] = '\0';
    for (int labels = 0; labels < 64; labels++) {
        if (position >= length) {
            return false;
        }
        unsigned label = data[position];
        if (label == 0) {
            *offset = resume != 0 ? resume : position + 1;
            return true;
        }
        if ((label & 0xc0) == 0xc0) {
            if (position + 1 >= length) {
                return false;
            }
            size_t target = (size_t)(label & 0x3f) << 8 | data[position + 1];
            if (target >= position) {
                return false; /* forward or self pointer: refuse */
            }
            if (resume == 0) {
                resume = position + 2;
            }
            position = target;
            continue;
        }
        if ((label & 0xc0) != 0 || position + 1 + label > length) {
            return false;
        }
        if (used > 0 && used + 1 < out_size) {
            out[used++] = '.';
        }
        for (size_t i = 0; i < label && used + 1 < out_size; i++) {
            unsigned char c = data[position + 1 + i];
            out[used++] = (c > 0x20 && c < 0x7f) ? (char)c : '.';
        }
        out[used] = '\0';
        position += 1 + label;
    }
    return false;
}

/* mDNS: the answers to "_services._dns-sd._udp.local" PTR list the service types offered. */
static bool identify_mdns(const unsigned char *data, size_t length, service_info *out)
{
    if (!is_dns_reply(data, length)) {
        return false;
    }
    set_text(out->service, sizeof out->service, "mdns");
    size_t questions = read_u16(data + 4);
    size_t records = (size_t)read_u16(data + 6) + read_u16(data + 8) + read_u16(data + 10);
    size_t offset = 12;
    char name[128];
    for (size_t q = 0; q < questions; q++) {
        if (!read_dns_name(data, length, &offset, name, sizeof name) || offset + 4 > length) {
            return true;
        }
        offset += 4; /* type, class */
    }
    for (size_t r = 0; r < records && r < 64; r++) {
        if (!read_dns_name(data, length, &offset, name, sizeof name) || offset + 10 > length) {
            return true;
        }
        unsigned type = read_u16(data + offset);
        size_t data_length = read_u16(data + offset + 8);
        offset += 10;
        if (offset + data_length > length) {
            return true;
        }
        if (type == 12 && strcmp(name, "_services._dns-sd._udp.local") == 0) {
            size_t pointer_offset = offset;
            char service_type[128];
            if (read_dns_name(data, length, &pointer_offset, service_type, sizeof service_type)) {
                size_t type_length = strlen(service_type);
                if (type_length > 6 && strcmp(service_type + type_length - 6, ".local") == 0) {
                    service_type[type_length - 6] = '\0'; /* "_ipp._tcp.local" -> "_ipp._tcp" */
                }
                append_text(out->info, sizeof out->info, ", ", service_type);
            }
        }
        offset += data_length;
    }
    return true;
}

/* NTP: mode 4 = server reply. The first byte also carries the protocol version. */
static bool identify_ntp(const unsigned char *data, size_t length, service_info *out)
{
    if (length < 48 || ((data[0] & 0x07) != 4 && (data[0] & 0x07) != 5)) {
        return false;
    }
    unsigned version = (data[0] >> 3) & 0x07;
    unsigned stratum = data[1];
    set_text(out->service, sizeof out->service, "ntp");
    if (stratum == 0 || stratum > 15) {
        snprintf(out->info, sizeof out->info, "NTPv%u, unsynchronized", version);
        return true;
    }
    snprintf(out->info, sizeof out->info, "NTPv%u, stratum %u", version, stratum);
    if (stratum == 1) {
        /* Stratum 1: the reference ID is a clock source such as "GPS" or "PPS", padded with NULs. */
        char source[5];
        size_t source_length = 0;
        while (source_length < 4 && data[12 + source_length] != '\0') {
            source_length++;
        }
        copy_text(source, sizeof source, data + 12, source_length);
        append_text(out->info, sizeof out->info, ", ", source);
    }
    return true;
}

/*
 * NetBIOS node status reply: a list of 18-byte entries, a 15-character name, a
 * 1-byte suffix and 2 flag bytes. Suffix 0x00 without the group flag is the
 * computer name; suffix 0x00 with the group flag is the workgroup or domain.
 */
static bool identify_netbios(const unsigned char *data, size_t length, service_info *out)
{
    if (length < 12 || data[0] != 0x12 || data[1] != 0x34 || (data[2] & 0x80) == 0) {
        return false;
    }
    set_text(out->service, sizeof out->service, "netbios-ns");
    size_t offset = 12;
    if (offset < length && data[offset] == 0x20) {
        offset += 34; /* length byte, 32 encoded characters, terminating 0 */
    } else if (offset + 1 < length && (data[offset] & 0xc0) == 0xc0) {
        offset += 2;
    } else {
        return true;
    }
    offset += 10; /* type, class, TTL, data length */
    if (offset >= length) {
        return true;
    }
    size_t names = data[offset++];
    char computer[16] = "";
    char group[16] = "";
    for (size_t i = 0; i < names && offset + 18 <= length; i++, offset += 18) {
        const unsigned char *entry = data + offset;
        bool is_group = (entry[16] & 0x80) != 0;
        if (entry[15] != 0x00) {
            continue;
        }
        if (!is_group && computer[0] == '\0') {
            copy_text(computer, sizeof computer, entry, 15);
        } else if (is_group && group[0] == '\0') {
            copy_text(group, sizeof group, entry, 15);
        }
    }
    if (computer[0] != '\0') {
        append_text(out->info, sizeof out->info, ", ", "name ");
        append_text(out->info, sizeof out->info, "", computer);
    }
    if (group[0] != '\0') {
        append_text(out->info, sizeof out->info, ", ", "group ");
        append_text(out->info, sizeof out->info, "", group);
    }
    return true;
}

/*
 * SSDP answers like HTTP. Its SERVER header is "OS/version UPnP/1.x
 * product/version": the last word names the software, the first the OS.
 */
static bool identify_ssdp(const unsigned char *data, size_t length, service_info *out)
{
    if (!has_prefix(data, length, "HTTP/1.")) {
        return false;
    }
    set_text(out->service, sizeof out->service, "ssdp");
    size_t value_length = 0;
    const unsigned char *server = find_header(data, length, "Server", &value_length);
    if (server == NULL) {
        return true;
    }
    /* Split into words; keep the last non-UPnP word as product, the others as info. */
    const unsigned char *words[8];
    size_t lengths[8];
    size_t count = 0;
    size_t i = 0;
    while (i < value_length && count < 8) {
        while (i < value_length && server[i] == ' ') {
            i++;
        }
        size_t start = i;
        while (i < value_length && server[i] != ' ') {
            i++;
        }
        if (i > start) {
            words[count] = server + start;
            lengths[count] = i - start;
            count++;
        }
    }
    size_t product_word = count;
    for (size_t w = count; w > 0; w--) {
        if (!(lengths[w - 1] >= 5 && strncasecmp((const char *)words[w - 1], "UPnP/", 5) == 0)) {
            product_word = w - 1;
            break;
        }
    }
    for (size_t w = 0; w < count; w++) {
        if (w == product_word) {
            service_info split;
            memset(&split, 0, sizeof split);
            split_product_token(words[w], lengths[w], &split);
            memcpy(out->product, split.product, sizeof out->product);
            memcpy(out->version, split.version, sizeof out->version);
        } else if (count > 1 && !(lengths[w] >= 5 && strncasecmp((const char *)words[w], "UPnP/", 5) == 0)) {
            char word[DETECTED_INFO_SIZE];
            copy_text(word, sizeof word, words[w], lengths[w]);
            append_text(out->info, sizeof out->info, " ", word);
        }
    }
    return true;
}

bool identify_udp_reply(uint16_t port, const unsigned char *data, size_t length, service_info *out)
{
    memset(out, 0, sizeof *out);
    bool found = false;
    switch (port) {
    case 53:
        found = identify_dns(data, length, out);
        break;
    case 123:
        found = identify_ntp(data, length, out);
        break;
    case 137:
        found = identify_netbios(data, length, out);
        break;
    case 1900:
        found = identify_ssdp(data, length, out);
        break;
    case 5353:
        found = identify_mdns(data, length, out);
        break;
    default:
        break;
    }
    if (!found) {
        memset(out, 0, sizeof *out);
    }
    return found;
}

/* ---- display ---------------------------------------------------------------------- */

void format_detected_version(const service_info *info, char *out, size_t out_size)
{
    if (out_size == 0) {
        return;
    }
    out[0] = '\0';
    append_text(out, out_size, " ", info->product);
    append_text(out, out_size, " ", info->version);
    if (info->info[0] == '\0') {
        return;
    }
    if (out[0] == '\0') {
        append_text(out, out_size, "", info->info);
    } else {
        append_text(out, out_size, " (", info->info);
        append_text(out, out_size, "", ")");
    }
}
