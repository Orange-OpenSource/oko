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

struct tcpopt_t {
    unsigned char msskind;
    unsigned char msslength;
    unsigned short mss;
    unsigned char nop1;
    unsigned char wskind;
    unsigned char wslength;
    unsigned char ws;
    unsigned char nop2;
    unsigned char nop3;
    unsigned char sokkind;
    unsigned char soklength;
};

static inline uint16_t
bpf_ntohs(uint16_t val) {
    return (val << 8) | (val >> 8);
}

uint64_t entry(void *pkt, uint64_t pkt_len) {
    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header + 1);
    struct tcphdr *tcphdr =(void *)(iphdr + 1 );
    struct tcpopt_t *tcpopt = (void *)(tcphdr + 1);

    uint64_t access_size = sizeof(*ether_header) + sizeof(*iphdr) + sizeof(*tcphdr) + sizeof(*tcpopt);
    if (pkt_len < access_size) {
        return 1;
    }

    int maskzero =  1 << 3;
    int mask_n = iphdr->tos & maskzero;
    int zero = mask_n >> 3;
    int df = (bpf_ntohs(iphdr->frag_off) & (1 << 14)) >> 14;
                    
    if((iphdr->ttl <= 128) && (iphdr->ttl > 93) && ((iphdr->ihl) == 5) && (tcphdr->window == 8192) && ((df) != 0) && ((zero) == 0) && ((bpf_ntohs(iphdr->tot_len) - ((iphdr->ihl) * 4) - (tcphdr->doff * 4)) == 0) && (tcpopt->msskind == 2) && (tcpopt->nop1 == 1) && (tcpopt->wskind == 3) && (tcpopt->nop2 == 1) && (tcpopt->nop3 == 1) && (tcpopt->sokkind == 4)){
        return 0;
    }
    return 1;
}