#include "services.h"

#include <arpa/inet.h> /* htons */
#include <netdb.h>     /* getservbyport, endservent */
#include <stddef.h>    /* NULL */

const char *lookup_service_name(uint16_t port)
{
    /*
     * getservbyport reads /etc/services. It expects the port in network
     * byte order, the same order used inside packets, hence htons().
     * The result lives in a static buffer inside the C library.
     */
    const struct servent *entry = getservbyport(htons(port), "tcp");
    if (entry == NULL || entry->s_name == NULL) {
        return "unknown";
    }
    return entry->s_name;
}

void close_service_database(void)
{
    endservent(); /* closes /etc/services if getservbyport left it open */
}
