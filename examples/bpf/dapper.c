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

#define TOLERATED_NB_SENT_SLOW 3
#define TOLERATED_B_SENT_SLOW 3
#define MSS_DEFAULT 14660
#define MAX_ENTRIES 40000
//Expected minimal use of the client advertised window size
#define TOLERATED_MIN_USAGE 30

//Uncomment this line for debug
// #define PRINTF(X,Y) ubpf_printf(X,Y)
#define PRINTF(X,Y)

//Uncomment this line for a hashmap instead of an array
#define HASHMAP
//Uncomment to ask dapper to calculate diagnosis (to print, it requires PRINTF activated)
// #define DIAG_ON

#ifdef DIAG_ON
    //Expepected RTT for a given connection (empiric value dependant of the network)
    #define EXPECTED_RTT 10
    //Expepected app sending rate for a given application (empiric value dependant of SLAs)
    #define TOLERATED_SLOW_APP_RT 100
    //static inline void diagnosis(stat Struct_stat stat, uint16_t tot_len);
#endif

#define BPF_ATTR_IS_KEY 0
#define BPF_ATTR_IS_HASH 1

static void *(*ubpf_map_lookup)(const void *, const void *) = (void *)1;
static int (*ubpf_map_update)(void *, const void *, void *) = (void *)2;
static int (*ubpf_map_delete)(void *, const void *) = (void *)3;
static uint32_t (*ubpf_hash)(const void *, uint64_t) = (void *)6;
static uint64_t (*ubpf_time_get_ns)() = (void *)5;
static void (*ubpf_printf)(const char *fmt, ...) = (void *)7;

struct stats {
    unsigned int senderIP;
    unsigned int MSS;

    unsigned int cSeqTimeStamp;
    unsigned int cSeqNum;

    unsigned int cFlightSize;
    unsigned int pFlightSize;

    unsigned short cReactiontime;

    //Why sending rate is unset
    /*unsigned short pSendingRate;
    unsigned short cSendingRate;*/

    unsigned char underWindow;
    unsigned char fullWindow;
    unsigned char dupAck;

    unsigned short inf_cwnd;
    unsigned int cAckTimeStamp;
    unsigned int cAckSeqnum;

    unsigned short rwnd;
    unsigned short cRTT;
    //unsigned short pRTT;
};
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
struct connection_id_struct {
    uint32_t saddr;
    uint32_t daddr;
    unsigned short source;
    unsigned short dest;
};

struct ubpf_map_def knownTroubleSomeConnection = {
#ifndef HASHMAP
    .type = UBPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
#else
    .type = UBPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(struct connection_id_struct),
#endif
    .value_size = sizeof(struct stats),
    .max_entries = MAX_ENTRIES,
    .nb_hash_functions = 0,
};

uint64_t entry(void *pkt, uint64_t pkt_len) {
    int rc;

    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header  + 1);
    struct tcphdr *tcphdr = (void *)(iphdr + 1);
    struct connection_id_struct conn;

    uint64_t access_size = sizeof(*ether_header) + sizeof(*iphdr) + sizeof(*tcphdr);
    if (pkt_len < access_size) {
        return 0;
    }

    unsigned int saddr = iphdr->saddr;
    unsigned int daddr = iphdr->daddr;
    unsigned short sport = tcphdr->source;
    unsigned short dport = tcphdr->dest;

    if(saddr < daddr) {
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

    struct stats *stat;
#ifdef HASHMAP
    stat = ubpf_map_lookup(&knownTroubleSomeConnection, &conn);
#else
    uint32_t hash = ubpf_hash(&conn, sizeof(struct connection_id_struct));
    hash = hash % MAX_ENTRIES;
    stat = ubpf_map_lookup(&knownTroubleSomeConnection, &hash);
#endif
    if(stat) {
#ifdef HASHMAP
        if (tcphdr->fin == 1 && tcphdr->ack == 1) {
            ubpf_map_delete(&knownTroubleSomeConnection, &conn);
            return 0;
        }
#endif
        if(iphdr->daddr == stat->senderIP) {
            if (tcphdr->ack_seq > stat->cAckSeqnum) {
                stat->dupAck = 0;
                stat->cAckSeqnum = tcphdr->ack_seq;
                stat->cAckTimeStamp = ubpf_time_get_ns();
                stat->rwnd = tcphdr->window;
                //stat->pRTT = stat->cRTT;
                stat->cRTT = stat->cAckTimeStamp - stat->cSeqTimeStamp;
                /*stat->cSendingRate = stat->pSendingRate;
                if (stat->cRTT != 0) {
                    stat->cSendingRate = stat->cFlightSize / stat->cRTT;
                }*/
            } else {
                stat->dupAck++;
            }
        } else {
            if (tcphdr->seq > stat->cSeqNum) {
                stat->cSeqTimeStamp = ubpf_time_get_ns();
                stat->cReactiontime = stat->cSeqTimeStamp - stat->cAckTimeStamp;
                stat->cSeqNum = tcphdr->seq;
                stat->pFlightSize = stat->cFlightSize;
                stat->cFlightSize = stat->cSeqNum - stat->cAckSeqnum;
                if (stat->cFlightSize > stat->inf_cwnd) {
                    stat->inf_cwnd = stat->cFlightSize;
                }
                if(stat->cFlightSize < (TOLERATED_MIN_USAGE*stat->rwnd)/100){
                    stat->underWindow++;
                }
                else if(stat->cFlightSize == stat->rwnd){
                    stat->fullWindow++;
                }
                else{
                stat->underWindow=0;
                stat->fullWindow=0;
                }
                /*stat->cSendingRate = stat->pSendingRate;
                if (stat->cRTT) {
                    stat->cSendingRate = stat->cFlightSize / stat->cRTT;
                }*/
            } else {
                switch (stat->dupAck) {
                case 3:
                    if (stat->pFlightSize) {
                        stat->inf_cwnd = (stat->cFlightSize / stat->pFlightSize) * stat->inf_cwnd;
                    } else {
                        stat->inf_cwnd /= 2;
                    }
                    break;
                case 1:
                    stat->inf_cwnd = stat->MSS;
                    break;
                }
            }
        }
#ifdef DIAG_ON
        uint64_t results = 10;
        //error_senderslowreaction_time
        if (stat->underWindow > TOLERATED_NB_SENT_SLOW && stat->cReactiontime < TOLERATED_SLOW_APP_RT) {
            PRINTF("%d", 10);
        }
        //error_senderslowcpu
        if (stat->underWindow > TOLERATED_NB_SENT_SLOW) {
            PRINTF("%d", 20);
        }
        //error_senderbacklogged
        if (stat->fullWindow > TOLERATED_B_SENT_SLOW) {
            PRINTF("%d", 40);
        }
        //Use counters of happening conditions? seems better for consistency and threshold definition
        //error_back logged, don't consume all bandwitdh (could be a counter)
        if (stat->cFlightSize < stat->rwnd && stat->rwnd < stat->inf_cwnd) {
            PRINTF("%d", 50);
        }
        //error_small_bandwidth
        if (stat->cRTT < EXPECTED_RTT) {
            PRINTF("%d", 60);
        }
        //error_senderslowcpu
        if (iphdr->tot_len < stat->inf_cwnd) {
            PRINTF("%d", 70);
        }
        //error_networkcongestion
        if (stat->inf_cwnd < stat->rwnd) {
            PRINTF("%d", 80);
        }
#endif
    } else {
        struct stats new_stat = {0};
        new_stat.senderIP = iphdr->daddr;
        new_stat.MSS = MSS_DEFAULT;
#ifdef HASHMAP
        rc = ubpf_map_update(&knownTroubleSomeConnection, &conn, &new_stat);
#else
        rc = ubpf_map_update(&knownTroubleSomeConnection, &hash, &new_stat);
#endif
        if (rc) {
            PRINTF("error: %d", rc);
        }
        return 0;
    }
    return 0;
}
