#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**************************************************
 * BEGIN TYPES FROM APPLE HEADER
 **************************************************/

#define    DNS_PTR(type, name)                \
    union {                        \
        type        name;            \
        uint64_t    _ ## name ## _p;    \
    }

#define    DNS_VAR(type, name)                \
    type    name


#pragma pack(4)
typedef struct {
    struct in_addr    address;
    struct in_addr    mask;
} dns_sortaddr_t;
#pragma pack()


#pragma pack(4)
typedef struct {
    DNS_PTR(char *,            domain);    /* domain */
    DNS_VAR(int32_t,        n_nameserver);    /* # nameserver */
    DNS_PTR(struct sockaddr **,    nameserver);
    DNS_VAR(uint16_t,        port);        /* port (in host byte order) */
    DNS_VAR(int32_t,        n_search);    /* # search */
    DNS_PTR(char **,        search);
    DNS_VAR(int32_t,        n_sortaddr);    /* # sortaddr */
    DNS_PTR(dns_sortaddr_t **,    sortaddr);
    DNS_PTR(char *,            options);    /* options */
    DNS_VAR(uint32_t,        timeout);    /* timeout */
    DNS_VAR(uint32_t,        search_order);    /* search_order */
    DNS_VAR(uint32_t,        if_index);
    DNS_VAR(uint32_t,        flags);
    DNS_VAR(uint32_t,        reach_flags);    /* SCNetworkReachabilityFlags */
    DNS_VAR(uint32_t,        service_identifier);
    DNS_PTR(char *,            cid);        /* configuration identifer */
    DNS_PTR(char *,            if_name);    /* if_index interface name */
} dns_resolver_t;
#pragma pack()

#pragma pack(4)
typedef struct {
    DNS_VAR(int32_t,        n_resolver);        /* resolver configurations */
    DNS_PTR(dns_resolver_t **,    resolver);
    DNS_VAR(int32_t,        n_scoped_resolver);    /* "scoped" resolver configurations */
    DNS_PTR(dns_resolver_t **,    scoped_resolver);
    DNS_VAR(uint64_t,        generation);
    DNS_VAR(int32_t,        n_service_specific_resolver);
    DNS_PTR(dns_resolver_t **,    service_specific_resolver);
    DNS_VAR(uint32_t,        version);
} dns_config_t;
#pragma pack()

/**************************************************
 * END TYPES FROM APPLE HEADER
 **************************************************/

#define field_info(type, field)                \
    printf("%-15s\t%-30s\toffset=%lu\tsizeof=%lu\n", \
            #type,                             \
            #field,                            \
            offsetof(type, field) ,            \
            sizeof ((type *)0)->field          \
    )

int main(void) {
    printf("sizeof(dns_config_t)=%lu\n", sizeof(dns_config_t));
    field_info(dns_config_t, n_resolver);
    field_info(dns_config_t, resolver);
    field_info(dns_config_t, n_scoped_resolver);
    field_info(dns_config_t, scoped_resolver);
    field_info(dns_config_t, generation);
    field_info(dns_config_t, n_service_specific_resolver);
    field_info(dns_config_t, service_specific_resolver);
    field_info(dns_config_t, version);

    printf("\n");

    printf("sizeof(dns_resolver_t)=%lu\n", sizeof(dns_resolver_t));
    field_info(dns_resolver_t, domain);
    field_info(dns_resolver_t, n_nameserver);
    field_info(dns_resolver_t, nameserver);
    field_info(dns_resolver_t, port);
    field_info(dns_resolver_t, n_search);
    field_info(dns_resolver_t, search);
    field_info(dns_resolver_t, n_sortaddr);
    field_info(dns_resolver_t, sortaddr);
    field_info(dns_resolver_t, options);
    field_info(dns_resolver_t, timeout);
    field_info(dns_resolver_t, search_order);
    field_info(dns_resolver_t, if_index);
    field_info(dns_resolver_t, flags);
    field_info(dns_resolver_t, reach_flags);
    field_info(dns_resolver_t, service_identifier);
    field_info(dns_resolver_t, cid);
    field_info(dns_resolver_t, if_name);

    printf("\n");
    field_info(struct sockaddr, sa_len);
    field_info(struct sockaddr, sa_family);
    field_info(struct sockaddr, sa_data);
}
