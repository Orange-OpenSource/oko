#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

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

void* memcpy(void* dest, const void* src, size_t len);

struct vxlan_h {
    uint32_t flags_reserved;
    uint32_t vni_reserved;
};

/*
 * This program presents more complex example: VXLAN encapsulation. The aim is to show the VXLAN encapsulation, so the
 * outer Ethernet and IP headers are just a simple copy of inner Etherner/IP headers. In the real-world application
 * outer Ethernet/IP headers should be filled with addresses of tunnel endpoints.
 * FIXME: the example can contain some bugs (e.g. calculation of checksum or packet length fields).
 */
uint64_t entry(void *ctx, uint64_t pkt_len)
{
    bool pass = true;

    void *pkt = ubpf_packet_data(ctx);
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr)) {
        return 1;
    }

    size_t head_len = sizeof(struct vxlan_h) + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
    pkt = ubpf_adjust_head(ctx, head_len);
    struct ether_header *new_eth = (void *) pkt;
    memcpy(new_eth, (char *)new_eth + head_len, sizeof(struct ether_header));

    struct iphdr *new_ip = (void *)(new_eth + 1);
    memcpy(new_ip, (char *)new_eth + head_len + sizeof(struct ether_header), sizeof(struct iphdr));
    new_ip->protocol = 0x11;

    struct udphdr *udp = (void *)(new_ip + 1);
    udp->uh_sport = bpf_htons(5555); // random source UDP port
    udp->uh_dport = bpf_htons(4789); // VXLAN UDP port
    size_t udp_len = pkt_len + sizeof(struct udphdr) + sizeof(struct vxlan_h);
    udp->uh_ulen  = bpf_htons(udp_len);

    struct vxlan_h *vxlan = (void *)(udp + 1);
    // Set VXLAN flags=0x11, reserved fields fill with zeros
    vxlan->flags_reserved = bpf_htonl(0x11000000);
    // Set VXLAN VNI=17, reserved fields fill with zeros
    vxlan->vni_reserved = bpf_htonl(0x00001100);

    return pass;
}
