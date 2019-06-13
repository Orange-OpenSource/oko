#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

enum ubpf_map_type {
    UBPF_MAP_TYPE_ARRAY = 1,
    UBPF_MAP_TYPE_BLOOMFILTER = 2,
    UBPF_MAP_TYPE_COUNTMIN = 3,
    UBPF_MAP_TYPE_HASHMAP = 4,
};

struct ubpf_map_def {
    enum ubpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int nb_hash_functions;
};

enum actions {
    DROP = 1,
    PASS = 2,
};

struct action_t {
    enum actions value;
};

struct match_key_t {
    uint32_t ip_addr;
};

struct ubpf_map_def lookup_table = {
        .type = UBPF_MAP_TYPE_HASHMAP,
        .key_size = sizeof(struct match_key_t),
        .value_size = sizeof(struct action_t),
        .max_entries = 1000,
        .nb_hash_functions = 0,
};

static void *(*ubpf_map_lookup)(const void *, const void *) = (void *)1;
static void (*ubpf_printf)(const char *fmt, ...) = (void *)7;

static inline uint32_t
bpf_ntohl(uint32_t val) {
    return ((uint32_t)((((uint32_t)(val) & (uint32_t)0x000000ffUL) << 24) |
                       (((uint32_t)(val) & (uint32_t)0x0000ff00UL) <<  8) |
                       (((uint32_t)(val) & (uint32_t)0x00ff0000UL) >>  8) |
                       (((uint32_t)(val) & (uint32_t)0xff000000UL) >> 24)));
}

uint64_t entry(void *pkt, uint64_t pkt_len)
{
    bool pass = true;

    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header + 1);
    if (sizeof(struct ether_header) + sizeof(struct iphdr) < pkt_len) {
        return 1;
    }
    uint32_t daddr = iphdr->daddr;

    struct match_key_t match;
    match.ip_addr = bpf_ntohl(daddr);

    struct action_t *action = ubpf_map_lookup(&lookup_table, &match);

    if(action != NULL) {
        switch(action->value) {
            case PASS:
                pass = true;
                break;
            case DROP:
                pass = false;
                break;
        }
    }

    return pass;
}
