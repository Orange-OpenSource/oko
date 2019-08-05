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

#define VLAN_HDR_LEN 4
#define ETH_ADDR_LEN 6

static void (*ubpf_printf)(const char *fmt, ...) = (void *)7;
static void *(*ubpf_packet_data)(const void *) = (void *)9;
static void *(*ubpf_adjust_head)(const void *, uint64_t) = (void *)8;

void* memmove(void* dest, const void* src, size_t len);

/*
 * The example shows VLAN tagging. The BPF program replaces Ethernet header with VLAN-tagged L2 header.
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

    struct vlan_eth {
        u_int8_t  ether_dhost[6];	/* destination eth addr	*/
        u_int8_t  ether_shost[6];	/* source ether addr	*/
        uint16_t h_vlan_ethtype;
        uint16_t h_vlan_TCI;
        uint16_t ethtype;
    };

    pkt = ubpf_adjust_head(ctx, VLAN_HDR_LEN);

    struct vlan_eth *veh = (void *) pkt;

    memmove(veh, (char *)veh + VLAN_HDR_LEN, 2 * ETH_ADDR_LEN);
    veh->h_vlan_TCI = bpf_htons(20); // set VLAN TCI=20
    veh->h_vlan_ethtype = bpf_htons(0x8100); // set EtherType to VLAN

    return pass;
}

