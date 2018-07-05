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
#include <inttypes.h>
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

struct bucket_t {
    uint64_t ts;
    uint64_t count;
};

struct ubpf_map_def buckets = {
    .type = UBPF_MAP_TYPE_HASHMAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct bucket_t),
    .max_entries = 1000,
    .nb_hash_functions = 0,
};

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define BUCKET_SIZE 10000
/* Regeneration rate for the bucket in packet per second.
 * Bucket is updated every 1 ms.
 **/
// initially at 100000L
#define GENERATION_RATE 10000L

static void *(*ubpf_map_lookup)(const void *, const void *) = (void *)1;
static int (*ubpf_map_update)(const void *, const void *, const void *) = (void *)2;
static uint64_t (*ubpf_time_get_ns)(void) = (void *)5;
static void (*ubpf_printf)(const char *fmt, ...) = (void *)7;

uint64_t entry(void *pkt, uint64_t pkt_len)
{
    uint64_t count, time_diff;
    struct bucket_t *bucket;
    uint64_t ts = ubpf_time_get_ns();
    uint32_t unit = 1;

    struct ether_header *ether_header = (void *)pkt;
    struct iphdr *iphdr = (void *)(ether_header + 1);
    if (sizeof(struct ether_header) + sizeof(struct iphdr) < pkt_len) {
        return 1;
    }
    uint32_t saddr = iphdr->saddr;

    bucket = ubpf_map_lookup(&buckets, &saddr);

    if (!bucket) {
        struct bucket_t b = {
            .count = BUCKET_SIZE - unit,
            .ts = ts,
        };
        ubpf_map_update(&buckets, &saddr, &b);
        return 0;
    }

    count = bucket->count;
    time_diff = ts - bucket->ts;
    if (time_diff > 10 * 1000000L) {
        bucket->count = MIN(BUCKET_SIZE, bucket->count + GENERATION_RATE * time_diff / 1000000000L);
        bucket->ts = ts;
    }

    if (count >= unit) {
        bucket->count -= unit;
        return 0;
    }
    return 1; // Drop
}
