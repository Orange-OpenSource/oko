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
#ifndef BPF_H
#define BPF_H 1

#include <stdint.h>

#include "util.h"
#include "bpf/ubpf.h"
#include "bpf/ubpf_int.h"
#include "dp-packet.h"
#include "bpf/lookup3.h"

#define FILTER_PROG_CHAIN_MAX 256

struct filter_prog {
    struct ubpf_vm *vm;   /* uBPF VM to execute the filter program. */
    ovs_be16 fp_instance_id; /* ID of this filter program instance
                              * (specific to the rule). */
    bpf_result expected_result; /* Expected result from the execution
                                 * of the filter program. */
    struct ovs_list filter_prog_node;
};

struct ubpf_vm *create_ubpf_vm(const ovs_be16 filter_prog);
bool load_filter_prog(struct ubpf_vm *vm, size_t code_len, char *code);
struct filter_prog *filter_prog_chain_lookup(struct ovs_list **filter_prog_chain,
                                             const ovs_be16 fp_instance_id,
                                             int last_fp_pos);
bool filter_prog_chain_add(struct ovs_list **filter_prog_chain,
                           const ovs_be16 fp_instance_id, struct ubpf_vm *vm,
                           bpf_result expected_result);
void filter_prog_chain_free(struct ovs_list *);
void *ubpf_map_lookup(const struct ubpf_map *map, void *key);
int ubpf_map_update(struct ubpf_map *map, const void *key, void *item);

static inline bool
ubpf_is_empty(struct ubpf_vm *vm)
{
    return vm->insts == NULL;
}

static inline bpf_result
filter_packet(struct ubpf_vm *vm, const struct dp_packet *packet)
{
    char *mem = (char *) dp_packet_data(packet);
    size_t mem_len = sizeof(mem);

    uint64_t ret = vm->jitted(mem, mem_len);
    return (ret == 1)? BPF_MATCH : BPF_NO_MATCH;
}

static inline bpf_result
run_filter_prog(const ovs_be16 fp_instance_id, struct ubpf_vm *vm,
                const struct dp_packet *packet,
                bpf_result *hist_filter_progs)
{
    if (hist_filter_progs[fp_instance_id] != BPF_UNKNOWN) {
    /* The filter program has already been executed for this packet */
        return hist_filter_progs[fp_instance_id];
    }
    bpf_result result = filter_packet(vm, packet);
    hist_filter_progs[fp_instance_id] = result;
    return result;
}

static inline bool
matches_filter_prog_chain(const struct ovs_list *filter_prog_chain,
                          struct dp_packet *packet,
                          bpf_result *hist_filter_progs)
{
    struct filter_prog *fp;
    bpf_result result;
    LIST_FOR_EACH (fp, filter_prog_node, filter_prog_chain) {
        result = run_filter_prog(fp->fp_instance_id, fp->vm, packet,
                                 hist_filter_progs);
        if (result != fp->expected_result) {
            return false;
        }
    }
    return true;
}

#endif
