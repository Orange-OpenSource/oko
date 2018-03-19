/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <getopt.h>
#include <signal.h>

#include <config.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include "util.h"

#include <linux/tcp.h>
#include "bpf.h"
#include "bpf/ubpf_hashmap.h"

/* Number of packets to attempt to read from queue. */
#define BURST_SIZE  ((uint16_t)32)

/* Define common names for structures shared between ovs_dpdk and client. */
#define MP_CLIENT_RXQ_NAME "dpdkr%u_tx"
#define MP_CLIENT_TXQ_NAME "dpdkr%u_rx"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define PREFETCH_OFFSET 3

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

#define BPF_ATTR_IS_KEY 0
#define BPF_ATTR_IS_HASH 1

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

#define TOLERATED_NB_SENT_SLOW 3
#define TOLERATED_B_SENT_SLOW 3
#define MSS_DEFAULT 14660
#define MAX_ENTRIES 40000
//Expected minimal use of the client advertised window size
#define TOLERATED_MIN_USAGE 30

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

/* Our client id number - tells us which rx queue to read, and tx
 * queue to write to.
 */
static unsigned int client_id;

static unsigned long long nb_pkts = 0;
static unsigned long long nb_pkts_matched = 0;
static volatile int run = true;

/*
 * Given the rx queue name template above, get the queue name.
 */
static inline const char *
get_rx_queue_name(unsigned int id)
{
    /* Buffer for return value. */
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, sizeof(buffer), MP_CLIENT_RXQ_NAME, id);
    return buffer;
}

/*
 * Given the tx queue name template above, get the queue name.
 */
static inline const char *
get_tx_queue_name(unsigned int id)
{
    /* Buffer for return value. */
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, sizeof(buffer), MP_CLIENT_TXQ_NAME, id);
    return buffer;
}

/*
 * Print a usage message.
 */
static void
usage(const char *progname)
{
    printf("\nUsage: %s [EAL args] -- -n <client_id>\n", progname);
}

/*
 * Convert the client id number from a string to an usigned int.
 */
static int
parse_client_num(const char *client)
{
    if (str_to_uint(client, 10, &client_id)) {
        return 0;
    } else {
        return -1;
    }
}

/*
 * Parse the application arguments to the client app.
 */
static int
parse_app_args(int argc, char *argv[])
{
    int option_index = 0, opt = 0;
    char **argvopt = argv;
    const char *progname = NULL;
    static struct option lgopts[] = {
        {NULL, 0, NULL, 0 }
    };
    progname = argv[0];

    while ((opt = getopt_long(argc, argvopt, "n:", lgopts,
        &option_index)) != EOF) {
        switch (opt) {
            case 'n':
                if (parse_client_num(optarg) != 0) {
                    usage(progname);
                    return -1;
                }
                break;
            default:
                usage(progname);
                return -1;
        }
    }

    return 0;
}

void intHandler()
{
    run = false;
}

void *threadproc(void *arg)
{
    uint32_t last_nb_pkts = 0, tmp_nb_pkts;
    while(run)
    {
        sleep(1);
        tmp_nb_pkts = nb_pkts;
        if (tmp_nb_pkts - last_nb_pkts < 1000000L) {
            printf("%0.2f kpps\n", (tmp_nb_pkts - last_nb_pkts) / 1000.0);
        } else {
            printf("%0.2f Mpps\n", (tmp_nb_pkts - last_nb_pkts) / 1000000.0);
        }
        last_nb_pkts = tmp_nb_pkts;
    }
    return 0;
}

uint64_t
entry_p0f(const void *pkt) {
    struct ether_hdr *ether_header = (void *)pkt;
    struct ipv4_hdr *iphdr = (void *)(ether_header + 1);
    struct tcphdr *tcphdr = (void *)(iphdr + 1);

    int maskzero = 1 << 3;
    int mask_n = iphdr->type_of_service & maskzero;
    int zero = mask_n >> 3;
    int df = (ntohs(iphdr->fragment_offset) & (1 << 14)) >> 14;
    uint8_t ihl = iphdr->version_ihl & IPV4_HDR_IHL_MASK;

    if((iphdr->time_to_live <= 64) && (iphdr->time_to_live > 29) && (ihl == 5) && (ntohs(tcphdr->window) == 512) && (zero == 0) && (tcphdr->urg != 0) && (tcphdr->psh != 0) && ((ntohs(iphdr->total_length) - (ihl * 4) - (tcphdr->doff * 4)) == 0)){
        return true;
    }
    return false;
}

void
init_sffw(struct ubpf_map *map) {
    struct ubpf_map_def map_def = {
        .type = UBPF_MAP_TYPE_HASHMAP,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct connInfo),
        .max_entries = 10000,
        .nb_hash_functions = 0,
    };
    map->type = map_def.type;
    map->key_size = map_def.key_size;
    map->value_size = map_def.value_size;
    map->max_entries = map_def.max_entries;
    map->data = ubpf_hashmap_create(&map_def);
}

uint64_t
entry_sffw(struct ubpf_map *map, const void *pkt) {
    struct ether_hdr *ether_header = (void *)pkt;
    struct ipv4_hdr *iphdr = (void *)(ether_header + 1);
    struct tcphdr *tcphdr = (void *)(iphdr + 1);
    struct connection_id_struct conn;

    uint32_t saddr = iphdr->src_addr;
    uint32_t daddr = iphdr->dst_addr;
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
    struct connInfo *info = ubpf_hashmap_lookup(map, &conn);
    if (!info) {
        if (tcphdr->syn == 1 && tcphdr->ack == 0) {
        // It's a SYN
            struct connInfo new_info = {0};
            new_info.state = SYNSENT;
            new_info.server = iphdr->dst_addr;
            ubpf_hashmap_update(map, &conn, &new_info);
        }
        return 0;
    }
    if (iphdr->src_addr == info->server) {
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
                ubpf_hashmap_delete(map, &conn);
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
                ubpf_hashmap_delete(map, &conn);
            }
            return 1;
        }
    }
    return 0;
}

static uint64_t
ubpf_time_get_ns(void)
{
    struct timespec curr_time = {0, 0};
    uint64_t curr_time_ns = 0;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
    return curr_time_ns;
}

static uint32_t
ubpf_hash(void *item, unsigned int size)
{
    return hashlittle(item, size, 0);
}

void
init_dapper(struct ubpf_map *map) {
    struct ubpf_map_def map_def = {
        .type = UBPF_MAP_TYPE_HASHMAP,
        .key_size = sizeof(struct connection_id_struct),
        .value_size = sizeof(struct stats),
        .max_entries = 10000,
        .nb_hash_functions = 0,
    };
    map->type = map_def.type;
    map->key_size = map_def.key_size;
    map->value_size = map_def.value_size;
    map->max_entries = map_def.max_entries;
    map->data = ubpf_hashmap_create(&map_def);
}

uint64_t entry_dapper(struct ubpf_map *map, void *pkt) {
    int rc;

    struct ether_hdr *ether_header = (void *)pkt;
    struct ipv4_hdr *iphdr = (void *)(ether_header  + 1);
    struct tcphdr *tcphdr = (void *)(iphdr + 1);
    struct connection_id_struct conn;

    unsigned int saddr = iphdr->src_addr;
    unsigned int daddr = iphdr->dst_addr;
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
    struct stats *stat = ubpf_hashmap_lookup(map, &conn);
    if(stat) {
        if (tcphdr->fin == 1 && tcphdr->ack == 1) {
            ubpf_hashmap_delete(map, &conn);
            return 0;
        }
        if(iphdr->dst_addr == stat->senderIP) {
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
    } else {
        struct stats new_stat = {0};
        new_stat.senderIP = iphdr->dst_addr;
        new_stat.MSS = MSS_DEFAULT;
        rc = ubpf_hashmap_update(map, &conn, &new_stat);
        return 0;
    }
    return 0;
}

uint64_t entry_link(struct ubpf_map *map, void *pkt) {
    return 0;
}

/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
    struct rte_ring *rx_ring = NULL;
    struct rte_ring *tx_ring = NULL;
    int retval = 0;
    int rslt = 0;
    struct ubpf_map map = {};
    struct rte_mbuf *bufs[BURST_SIZE], *to_send[BURST_SIZE],
                    *to_free[BURST_SIZE];
    uint64_t (*fn)(struct ubpf_map *map, const void *pkt);

    signal(SIGINT, intHandler);
    pthread_t tid;
    pthread_create(&tid, NULL, &threadproc, NULL);

    if ((retval = rte_eal_init(argc, argv)) < 0) {
        return -1;
    }

    argc -= retval;
    argv += retval;

    if (argc < 2) {
        rte_exit(EXIT_FAILURE, "Missing argument for program to launch\n");
    }

    if (parse_app_args(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    rx_ring = rte_ring_lookup(get_rx_queue_name(client_id));
    if (rx_ring == NULL) {
        rte_exit(EXIT_FAILURE,
            "Cannot get RX ring - is server process running?\n");
    }

    tx_ring = rte_ring_lookup(get_tx_queue_name(client_id));
    if (tx_ring == NULL) {
        rte_exit(EXIT_FAILURE,
            "Cannot get TX ring - is server process running?\n");
    }

    RTE_LOG(INFO, APP, "Finished Process Init.\n\n");

    if (argv[1][0] == 's') {
        printf("Launching the stateful firewall!\n");
        init_sffw(&map);
        fn = entry_sffw;
    } else if (argv[1][0] == 'd') {
        printf("Launching Dapper!\n");
        init_dapper(&map);
        fn = entry_dapper;
    } else if (argv[1][0] == 'p') {
        printf("Launching the p0f TCP SYN filtering!\n");
        fn = entry_p0f;
    } else {
        printf("Acting as a simple link!\n");
        fn = entry_link;
    }

    printf("Client process %d handling packets\n", client_id);
    printf("[Press Ctrl-C to quit ...]\n");

    while (run) {
        uint16_t i, nb_rx = BURST_SIZE, nb_tx = 0, nb_rx_send = 0,
                 nb_rx_free = 0;

        /* Try dequeuing max possible packets first, if that fails, get the
         * most we can. Loop body should only execute once, maximum.
         */
        while (unlikely(rte_ring_dequeue_bulk(rx_ring, bufs, nb_rx) != 0) &&
            nb_rx > 0) {
            nb_rx = (uint16_t)RTE_MIN(rte_ring_count(rx_ring), BURST_SIZE);
        }

        if (unlikely(nb_rx == 0)) {
            continue;
        }

        for (i = 0; i < nb_rx; i++) {
            const void *pkt = rte_pktmbuf_mtod(bufs[i], void *);

            if (entry_p0f(pkt)) {
                to_free[nb_rx_free] = bufs[i];
                nb_rx_free++;
            } else {
                to_send[nb_rx_send] = bufs[i];
                nb_rx_send++;
            }
        }

        nb_pkts += nb_rx;
        nb_pkts_matched += nb_rx_free;

        for (i = 0; i < nb_rx_free; i++) {
            rte_pktmbuf_free(to_free[i]);
        }

        if (nb_rx_send > 0) {
            do {
                rslt = rte_ring_enqueue_bulk(tx_ring, to_send, nb_rx_send);
            } while (rslt == -ENOBUFS);
        }
    }

    printf("Packets received: %llu, %llu matched\n", nb_pkts, nb_pkts_matched);
}
