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

struct ubpf_vm *create_ubpf_vm(const ovs_be16 prog_id);
bool load_bpf_prog(struct ubpf_vm *vm, size_t code_len, char *code);
void *ubpf_map_lookup(const struct ubpf_map *map, void *key);
int ubpf_map_update(struct ubpf_map *map, const void *key, void *item);

static inline bool
ubpf_is_empty(struct ubpf_vm *vm)
{
    return vm->insts == NULL;
}

static inline bpf_result
ubpf_handle_packet(struct ubpf_vm *vm, const struct dp_packet *packet)
{
    char *mem = (char *) dp_packet_data(packet);
    size_t mem_len = sizeof(mem);

    uint64_t ret = vm->jitted(mem, mem_len);
    return (ret == 1)? BPF_MATCH : BPF_NO_MATCH;
}

static inline bool
run_bpf_prog(const struct dp_packet *packet, struct ubpf_vm *vm)
{
    bpf_result result = ubpf_handle_packet(vm, packet);
    return (result == BPF_MATCH) ? true : false;
}

#endif
