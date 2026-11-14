#include "cli.h"

#include <errno.h>  /* errno, ERANGE */
#include <getopt.h> /* getopt_long, struct option */
#include <limits.h> /* INT_MAX */
#include <stdlib.h> /* calloc, free, strtol */
#include <string.h> /* strchr, strlen */

#include "discovery.h" /* DEFAULT_DISCOVER_PORTS */
#include "targets.h"
#include "utils.h"

#define PORT_MIN 1
#define PORT_MAX 65535
#define PORT_DIGITS_MAX 5 /* "65535" */

/* Values for long options that have no short letter. */
enum {
    OPTION_TIMEOUT = 1000,
    OPTION_THREADS,
    OPTION_JSON,
    OPTION_TOP_PORTS,
    OPTION_BANNER,
    OPTION_OPEN,
    OPTION_DISCOVER,
    OPTION_DISCOVER_PORTS,
    OPTION_SERVICE_VERSION,
};

void print_usage(FILE *stream, const char *program_name)
{
    fprintf(stream,
            "Janus %s - TCP connect and UDP port scanner\n"
            "\n"
            "Usage: %s -t <target> [options]\n"
            "\n"
            "Options:\n"
            "  -t, --target <spec>   host name, IPv4/IPv6 address, list (a,b,c) or IPv4\n"
            "                        CIDR block /%d-/32, e.g. 192.168.1.0/24 (required)\n"
            "  -p, --ports <list>    ports: 80 | 22,80,443 | 1-1024 | 22,80-90 (default %s)\n"
            "      --top-ports <n>   the n most common ports, 1-%d (instead of -p)\n"
            "  -u, --udp             scan UDP instead of TCP (no root needed). Default ports:\n"
            "                        the %d most common UDP ports; --top-ports takes 1-%d\n"
            "                        Silent ports are reported as open|filtered\n"
            "      --timeout <ms>    wait per port in milliseconds, %d-%d (default %d)\n"
            "      --threads <n>     parallel workers, 1-%d (default %d)\n"
            "      --banner          read a short greeting from open ports (HTTP ports\n"
            "                        get a HEAD request); nothing else is sent\n"
            "      --sv              identify what really runs on open ports: service,\n"
            "                        product and version (OpenSSH 9.6p1, nginx 1.24.0,\n"
            "                        TLS 1.3, MySQL, ...). Silent ports get a TLS and an\n"
            "                        HTTP probe; with --udp, replies are decoded\n"
            "      --open            with several hosts, list only hosts with open ports\n"
            "      --discover        first find which hosts answer (TCP probes, no root\n"
            "                        needed) and port-scan only those; down hosts are skipped\n"
            "      --discover-ports <list>\n"
            "                        ports to probe for --discover (default %s);\n"
            "                        implies --discover\n"
            "  -4 / -6               use only IPv4 / only IPv6 when resolving names\n"
            "      --json            print the result as JSON (open ports only)\n"
            "  -h, --help            show this help and exit\n"
            "  -v, --version         show the version and exit\n"
            "\n"
            "WARNING: Authorized use only. Scan only systems you own or have\n"
            "explicit permission to test. Unauthorized scanning may be illegal.\n",
            JANUS_VERSION, program_name, MIN_CIDR_PREFIX, DEFAULT_PORTS, TOP_PORTS_MAX,
            UDP_TOP_PORTS_MAX, UDP_TOP_PORTS_MAX, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, DEFAULT_TIMEOUT_MS,
            MAX_THREAD_COUNT, DEFAULT_THREAD_COUNT, DEFAULT_DISCOVER_PORTS);
}

/*
 * Parse the characters in [start, end) as a port number.
 * Only digits are accepted: no sign, no spaces, no empty string.
 * The length check makes integer overflow impossible: at most 5 digits
 * means at most 99999, which easily fits in a long.
 */
static int parse_port_number(const char *start, const char *end, uint16_t *port_out)
{
    size_t length = (size_t)(end - start);
    if (length == 0 || length > PORT_DIGITS_MAX) {
        return -1;
    }

    long value = 0;
    for (const char *cursor = start; cursor < end; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return -1;
        }
        value = value * 10 + (*cursor - '0');
    }

    if (value < PORT_MIN || value > PORT_MAX) {
        return -1;
    }
    *port_out = (uint16_t)value;
    return 0;
}

/* Parse one list item, "80" or "20-25", and mark its ports in 'selected'. */
static int parse_port_item(const char *start, const char *end, unsigned char *selected)
{
    /* Look for a '-' inside this item only (not past 'end'). */
    const char *dash = NULL;
    for (const char *cursor = start; cursor < end; cursor++) {
        if (*cursor == '-') {
            dash = cursor;
            break;
        }
    }

    uint16_t first;
    uint16_t last;
    if (dash == NULL) {
        if (parse_port_number(start, end, &first) != 0) {
            return -1;
        }
        last = first;
    } else {
        if (parse_port_number(start, dash, &first) != 0 ||
            parse_port_number(dash + 1, end, &last) != 0 || first > last) {
            return -1;
        }
    }

    /* Use an int loop counter: a uint16_t would wrap from 65535 to 0 forever. */
    for (int port = first; port <= last; port++) {
        selected[port] = 1;
    }
    return 0;
}

int parse_port_list(const char *text, uint16_t **ports_out, size_t *count_out)
{
    *ports_out = NULL;
    *count_out = 0;

    /*
     * One flag per possible port (index 0..65535). Marking flags instead of
     * appending to a list removes duplicates and sorts the ports for free.
     */
    unsigned char *selected = calloc(PORT_MAX + 1, sizeof *selected);
    if (selected == NULL) {
        print_error("out of memory");
        return -1;
    }

    /* Walk the string item by item, splitting on ','. Empty items are errors. */
    const char *item_start = text;
    for (;;) {
        const char *comma = strchr(item_start, ',');
        const char *item_end = comma != NULL ? comma : item_start + strlen(item_start);

        if (parse_port_item(item_start, item_end, selected) != 0) {
            print_error("invalid port specification '%.*s' in '%s' (ports are 1-%d)",
                        (int)(item_end - item_start), item_start, text, PORT_MAX);
            free(selected);
            return -1;
        }
        if (comma == NULL) {
            break;
        }
        item_start = comma + 1;
    }

    size_t count = 0;
    for (int port = PORT_MIN; port <= PORT_MAX; port++) {
        count += selected[port];
    }

    uint16_t *ports = calloc(count, sizeof *ports);
    if (ports == NULL) {
        print_error("out of memory");
        free(selected);
        return -1;
    }
    size_t index = 0;
    for (int port = PORT_MIN; port <= PORT_MAX; port++) {
        if (selected[port]) {
            ports[index++] = (uint16_t)port;
        }
    }

    free(selected);
    *ports_out = ports;
    *count_out = count;
    return 0;
}

/*
 * Parse a whole decimal string into an int within [min, max].
 * strtol reports overflow by returning LONG_MAX/LONG_MIN and setting
 * errno to ERANGE, so errno must be cleared before the call.
 */
static int parse_bounded_int(const char *text, int min, int max, int *value_out)
{
    if (text[0] == '\0' || text[0] == '+' || text[0] == '-' || text[0] == ' ') {
        return -1;
    }

    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno == ERANGE || *end != '\0' || value < min || value > max) {
        return -1;
    }
    *value_out = (int)value; /* safe: max is an int, so value fits */
    return 0;
}

void free_options(scan_options *options)
{
    free(options->ports); /* free(NULL) is allowed and does nothing */
    options->ports = NULL;
    options->port_count = 0;
    free(options->discover_ports);
    options->discover_ports = NULL;
    options->discover_port_count = 0;
}

parse_status parse_arguments(int argc, char *argv[], scan_options *options)
{
    const char *program_name = argv[0];
    const char *port_text = DEFAULT_PORTS;
    bool ports_given = false;
    const char *discover_port_text = DEFAULT_DISCOVER_PORTS;
    const char *top_text = NULL;
    int top_count = 0;

    options->target = NULL;
    options->ports = NULL;
    options->port_count = 0;
    options->timeout_ms = DEFAULT_TIMEOUT_MS;
    options->thread_count = DEFAULT_THREAD_COUNT;
    options->json_output = false;
    options->grab_banner = false;
    options->detect_version = false;
    options->open_only = false;
    options->family = 0;
    options->udp = false;
    options->discover = false;
    options->discover_ports = NULL;
    options->discover_port_count = 0;

    static const struct option long_options[] = {
        {"target", required_argument, NULL, 't'},
        {"ports", required_argument, NULL, 'p'},
        {"timeout", required_argument, NULL, OPTION_TIMEOUT},
        {"threads", required_argument, NULL, OPTION_THREADS},
        {"json", no_argument, NULL, OPTION_JSON},
        {"top-ports", required_argument, NULL, OPTION_TOP_PORTS},
        {"banner", no_argument, NULL, OPTION_BANNER},
        {"sv", no_argument, NULL, OPTION_SERVICE_VERSION},
        {"service-version", no_argument, NULL, OPTION_SERVICE_VERSION},
        {"udp", no_argument, NULL, 'u'},
        {"open", no_argument, NULL, OPTION_OPEN},
        {"discover", no_argument, NULL, OPTION_DISCOVER},
        {"discover-ports", required_argument, NULL, OPTION_DISCOVER_PORTS},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}, /* end marker */
    };

    /* Leading ':' lets us print our own message for a missing argument. */
    int option;
    while ((option = getopt_long(argc, argv, ":t:p:hv46u", long_options, NULL)) != -1) {
        switch (option) {
        case 't':
            options->target = optarg;
            break;
        case 'p':
            port_text = optarg;
            ports_given = true;
            break;
        case OPTION_TOP_PORTS:
            top_text = optarg; /* checked after the loop: the limit depends on --udp */
            break;
        case 'u':
            options->udp = true;
            break;
        case OPTION_BANNER:
            options->grab_banner = true;
            break;
        case OPTION_SERVICE_VERSION:
            options->detect_version = true;
            break;
        case OPTION_OPEN:
            options->open_only = true;
            break;
        case OPTION_DISCOVER:
            options->discover = true;
            break;
        case OPTION_DISCOVER_PORTS:
            options->discover = true; /* giving probe ports only makes sense with discovery */
            discover_port_text = optarg;
            break;
        case '4':
        case '6':
            if (options->family != 0 && options->family != option - '0') {
                print_error("-4 and -6 cannot be combined");
                return PARSE_ERROR;
            }
            options->family = option - '0';
            break;
        case OPTION_TIMEOUT:
            if (parse_bounded_int(optarg, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS,
                                  &options->timeout_ms) != 0) {
                print_error("invalid timeout '%s' (expected %d-%d milliseconds)",
                            optarg, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
                return PARSE_ERROR;
            }
            break;
        case OPTION_THREADS:
            if (parse_bounded_int(optarg, 1, MAX_THREAD_COUNT,
                                  &options->thread_count) != 0) {
                print_error("invalid thread count '%s' (expected 1-%d)",
                            optarg, MAX_THREAD_COUNT);
                return PARSE_ERROR;
            }
            break;
        case OPTION_JSON:
            options->json_output = true;
            break;
        case 'h':
            print_usage(stdout, program_name);
            return PARSE_EXIT_SUCCESS;
        case 'v':
            printf("janus %s\n", JANUS_VERSION);
            return PARSE_EXIT_SUCCESS;
        case ':':
            print_error("option '%s' needs a value", argv[optind - 1]);
            return PARSE_ERROR;
        default: /* '?' = unknown option */
            print_error("unknown option '%s' (try --help)", argv[optind - 1]);
            return PARSE_ERROR;
        }
    }

    if (optind < argc) {
        print_error("unexpected argument '%s' (try --help)", argv[optind]);
        return PARSE_ERROR;
    }
    if (options->target == NULL) {
        print_error("missing target, use -t <host> (try --help)");
        return PARSE_ERROR;
    }
    size_t target_length = strlen(options->target);
    if (target_length == 0 || target_length > 4096) {
        print_error("target must be 1-4096 characters long");
        return PARSE_ERROR;
    }

    if (options->discover &&
        parse_port_list(discover_port_text, &options->discover_ports, &options->discover_port_count) != 0) {
        return PARSE_ERROR;
    }

    if (options->udp && options->grab_banner) {
        print_error("--banner works only with TCP scans");
        return PARSE_ERROR;
    }

    int top_limit = options->udp ? UDP_TOP_PORTS_MAX : TOP_PORTS_MAX;
    if (top_text != NULL && parse_bounded_int(top_text, 1, top_limit, &top_count) != 0) {
        print_error("invalid --top-ports '%s' (expected 1-%d%s)", top_text, top_limit,
                    options->udp ? " for UDP" : "");
        return PARSE_ERROR;
    }
    if (ports_given && top_count > 0) {
        print_error("use either -p or --top-ports, not both");
        return PARSE_ERROR;
    }
    if (options->udp && !ports_given && top_count == 0) {
        top_count = UDP_TOP_PORTS_MAX; /* 1-1024 over UDP would be slow and mostly silent */
    }
    if (top_count > 0) {
        /* Reuse the list parser's sort and de-duplication through a text list. */
        const uint16_t *table = options->udp ? udp_top_ports : top_ports;
        char list[TOP_PORTS_MAX * 7];
        size_t used = 0;
        for (int i = 0; i < top_count; i++) {
            used += (size_t)snprintf(list + used, sizeof list - used, "%s%u", i ? "," : "",
                                     (unsigned)table[i]);
        }
        return parse_port_list(list, &options->ports, &options->port_count) == 0 ? PARSE_OK
                                                                                 : PARSE_ERROR;
    }
    if (parse_port_list(port_text, &options->ports, &options->port_count) != 0) {
        return PARSE_ERROR;
    }
    return PARSE_OK;
}
