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
#ifndef OPENFLOW_ORANGE_EXT_H
#define OPENFLOW_ORANGE_EXT_H 1

#include "openflow/openflow.h"
#include "openvswitch/types.h"


/* BPF_LOAD_PROG.
 *
 * BPF_LOAD_PROG allows applications to load BPF program
 * in Open vSwitch. Each BPF program is loaded into a uBPF VM.
 * OpenFlow rules can then reference these uBPF VMs by the BPF program id.
 * 
 * BPF programs are given to Open vSwitch as ELF files. ELF file headers
 * are necessary to preserve information on the memory to allocate (for maps)
 * and functions to link (for helpers). 
 */
struct ol_bpf_load_prog {
    ovs_be16 prog_id;  /* BPF program ID. */
    uint8_t pad[2];        /* Align to 64-bits. */
    ovs_be32 file_len;     /* Size of ELF file in packet. */
    /* Followed by:
     *   - Exactly file_len (possibly 0) bytes containing the ELF file. */
    /* uint8_t elf_file[...]; */ /* ELF file containing the filter program. */
};
OFP_ASSERT(sizeof(struct ol_bpf_load_prog) == 8);

/*
 * BPF_UPDATE_MAP.
 *
 * BPF_UPDATE_MAP allows to add a new map entry for the pre-defined map of the
 * BPF program installed in Open vSwitch. The BPF program is referenced by
 * program id and the map of the BPF program is referenced by map id.
 *
 * The application needs to provide at least one tuple (key, value) of
 * the correct size. The size of key and value is specified in the BPF program.
 */
struct ol_bpf_update_map {
    ovs_be16 prog_id;  /* BPF program ID. */
    ovs_be16 map_id; /* Map ID. */
    ovs_be32 key_size;
    ovs_be32 value_size;
    ovs_be32 nb_elems;
    /* Followed by:
     *   - Exactly nb_elems tuples (key, value) of total
     *     nb_elems * (key_size + value_size) bytes. */
    /* uint8_t entries[...]; */ /* Data containing the map
                                   entries (key + value). */
};
OFP_ASSERT(sizeof(struct ol_bpf_update_map) == 16);

#endif /* openflow/orange-ext.h */
