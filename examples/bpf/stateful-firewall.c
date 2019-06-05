/*
 * Copyright 2018 Orange
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_ENTRIES 10000
//#define PRINTF(X) ubpf_printf(X)
// #define PRINTF(str, args...) ubpf_printf(str, args)
#define PRINTF(X,Y)

enum bpf_map_type {
    BPF_MAP_TYPE_ARRAY = 1,
    BPF_MAP_TYPE_BLOOMFILTER = 2,
    BPF_MAP_TYPE_COUNTMIN = 3,
    BPF_MAP_TYPE_HASHMAP = 4,
};

struct bpf_map_def {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int nb_hash_functions;
};

static void *(*ubpf_map_lookup)(const void *, const void *) = (void *)1;
static int (*ubpf_map_update)(void *, const void *, void *) = (void *)2;
static int (*ubpf_map_delete)(void *, const void *) = (void *)3;

struct connection_id_struct {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t source;
    uint16_t dest;
};

enum state {
    SYNSENT = 1,
    SYNACKED,
    ESTABLISHED
};

struct connInfo {
    enum state state;
    uint32_t server;
};

struct bpf_map_def reg = {
    .type = BPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct connInfo),
    .max_entries = MAX_ENTRIES,
    .nb_hash_functions = 0,
};

/**
 * Returns 1 if connection is established, 0 otherwise.
 */
uint64_t entry(void *pkt, uint64_t pkt_len) {
    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header + 1);
    struct tcphdr *tcphdr = (void *)(iphdr + 1);
    struct connection_id_struct conn;

    uint64_t access_size = sizeof(*ether_header) + sizeof(*iphdr) + sizeof(*tcphdr);
    if (pkt_len < access_size) {
        return 0;
    }

    uint32_t saddr = iphdr->saddr;
    uint32_t daddr = iphdr->daddr;
    uint16_t sport = tcphdr->source;
    uint16_t dport = tcphdr->dest;

    if (saddr < daddr) {
        conn.saddr = saddr;
        conn.daddr = daddr;
    } else {
        conn.saddr = daddr;
        conn.daddr = saddr;
    }
    if (sport < dport) {
        conn.source = tcphdr->source;
        conn.dest = tcphdr->dest;
    } else {
        conn.source = tcphdr->dest;
        conn.dest = tcphdr->source;
    }

    // Checks if the connection is known.
    struct connInfo *info = ubpf_map_lookup(&reg, &conn);
    if(!info) {
        if (tcphdr->syn == 1 && tcphdr->ack == 0) {
        // It's a SYN
            struct connInfo new_info = {0};
            new_info.state = SYNSENT;
            new_info.server = iphdr->daddr;
            ubpf_map_update(&reg, &conn, &new_info);
        }
        return 0;
    } else if (iphdr->saddr == info->server) {
        switch (info->state) {
        case SYNSENT: // SYN Sent Awaiting SYN+ACK
            if (tcphdr->syn == 1 && tcphdr->ack == 1) {
            // It's a SYN+ACK
                info->state = SYNACKED;
            }
            return 0;
        case SYNACKED: // SYN+ACK Sent Awaiting ACK
            return 0;
        case ESTABLISHED: // Connection established, awaiting FIN
            if (tcphdr->fin == 1 && tcphdr->ack == 1) {
            // It's a FIN+ACK
                ubpf_map_delete(&reg, &conn);
            }
            return 1;
        }
    } else {
        switch (info->state) {
        case SYNSENT: // SYN Sent Awaiting SYN+ACK
            return 0;
        case SYNACKED: // SYN+ACK Sent Awaiting ACK
            if (tcphdr->syn == 0 && tcphdr->ack == 1) {
            // It's a ACK
                info->state = ESTABLISHED;
                return 1;
            }
            return 0;
        case ESTABLISHED: // Connection established, awaiting FIN
            if (tcphdr->fin == 1 && tcphdr->ack == 1) {
            // It's a FIN+ACK
                ubpf_map_delete(&reg, &conn);
            }
            return 1;
        }
    }
    return 0;
}
