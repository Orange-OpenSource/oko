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

/* BPF_UNLOAD_PROG.
 *
 * BPF_UNLOAD_PROG allows applications to unload BPF program
 * from Open vSwitch. Each BPF program is unloaded from a uBPF VM.
 * OpenFlow rules can then reference these uBPF VMs by the BPF program id.
 */
struct ol_bpf_unload_prog {
    ovs_be16 prog;  /* BPF program ID. */
    uint8_t pad[2];        /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct ol_bpf_unload_prog) == 4);

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

/*
 * BPF_DUMP_MAP_REQUEST.
 *
 * BPF_DUMP_MAP_REQUEST allows to create request to dump all map entries
 * for the all pre-defined maps of the BPF program installed in Open vSwitch.
 * The BPF program is referenced by filter program id.
 * Maps of BPF program are referenced by list of map ids
 * of exactly nb_elems number.
 *
 * The application needs to provide at least one map id.
 */
struct ol_bpf_dump_map_request {
    ovs_be16 prog;  /* BPF Filter program ID. */
    ovs_be16 nb_maps;
    /* Followed by:
     *   - Exactly nb_maps map_ids of total nb_maps * ovs_be16 bytes. */
    /* uint8_t entries[...]; */ /* Data containing the map ids. */
};
OFP_ASSERT(sizeof(struct ol_bpf_dump_map_request) == 4);

/*
 * BPF_DUMP_MAP_REPLY.
 *
 * BPF_DUMP_MAP_REPLY allows to create reply of all map entries for the all
 * pre-defined maps of the BPF program installed in Open vSwitch.
 * The BPF program is referenced by filter program id.
 * Maps entries are referenced by list of ol_bpf_dump_map structures
 * of exactly nb_maps number.
 */
struct ol_bpf_dump_map_reply {
    ovs_be16 prog;  /* Filter program ID. */
    ovs_be16 nb_maps;
    /* Followed by:
     *   - Exactly nb_maps ol_bpf_dump_maps of total
     *     nb_maps * ol_bpf_dump_map bytes. */
    /* uint8_t entries[...]; */ /* Data containing the ol_bpf_dump_maps. */
};
OFP_ASSERT(sizeof(struct ol_bpf_dump_map_reply) == 4);

/*
 * BPF_DUMP_MAP.
 *
 * BPF_DUMP_MAP keeps all map entries for the
 * pre-defined map of the BPF program installed in Open vSwitch.
 * The map of the BPF program is referenced by map id.
 */
struct ol_bpf_dump_map {
    ovs_be16 map;  /* Map ID. */
    uint8_t pad[2];
    ovs_be32 key_size;
    ovs_be32 value_size;
    ovs_be32 nb_elems;
    /* Followed by:
     *   - Exactly nb_elems * (key_size + value_size) bytes. */
    /* uint8_t entries[...]; */ /* Data containing the map entries (key + value). */
};
OFP_ASSERT(sizeof(struct ol_bpf_dump_map) == 16);

/*
 * BPF_DELETE_MAP.
 *
 * BPF_DELETE_MAP allows to delete a map entries for the pre-defined map of the
 * BPF program installed in Open vSwitch.
 * The BPF program is referenced by program id and
 * the map of the BPF program is referenced by map id.
 *
 * The application needs to provide at least one key of
 * the correct size. The size of key is specified in the BPF program.
 */
struct ol_bpf_delete_map {
    ovs_be16 prog;  /* BPF program ID. */
    ovs_be16 map; /* Map ID. */
    ovs_be32 key_size;
    ovs_be32 nb_elems;
    /* Followed by:
     *   - Exactly nb_elems key of total nb_elems * key_size bytes. */
    /* uint8_t entries[...]; */ /* Data containing the map keys. */
};
OFP_ASSERT(sizeof(struct ol_bpf_delete_map) == 12);

#endif /* openflow/orange-ext.h */
