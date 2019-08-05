#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define ___constant_swab16(x) ((uint16_t)(             \
    (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |          \
    (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

#define ___constant_swab32(x) ((uint32_t)(             \
    (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |        \
    (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |        \
    (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |        \
    (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define bpf_htons(d) (___constant_swab16((d)))
#define bpf_htonl(d) (___constant_swab32((d)))

static void (*ubpf_printf)(const char *fmt, ...) = (void *)7;
static void *(*ubpf_packet_data)(const void *) = (void *)9;
static void *(*ubpf_adjust_head)(const void *, uint64_t) = (void *)8;

void* memmove(void* dest, const void* src, size_t len);

/*
 * The example shows MPLS tunneling. The BPF program inserts MPLS header in-between Ethernet and IP headers.
 */
uint64_t entry(void *ctx, uint64_t pkt_len)
{
    bool pass = true;

    void *pkt = ubpf_packet_data(ctx);

    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header + 1);

    if (sizeof(struct ether_header) + sizeof(struct iphdr) < pkt_len) {
        return 1;
    }

    struct mpls_h {
        uint32_t lse;
    };

    // set MPLS UNICAST EtherType
    ether_header->ether_type = bpf_htons(0x8847);

    pkt = ubpf_adjust_head(ctx, sizeof(struct mpls_h));

    char * header = (void *) pkt;
    memmove(header, header + sizeof(struct mpls_h), sizeof(struct ether_header));

    struct ether_header *new_eth = (void *) header;
    // Set MPLS label=7, tc=5, s=1, ttl=64
    uint32_t lse = bpf_htonl(0x00007B40);
    struct mpls_h *mpls_hdr = (void *)(new_eth + 1);
    mpls_hdr->lse = lse;

    return pass;
}
