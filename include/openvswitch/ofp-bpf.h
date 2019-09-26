/*
 * Copyright 2019 Orange
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

#ifndef OVS_OFP_BPF_H
#define OVS_OFP_BPF_H 1

#include "openflow/orange-ext.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ofperr ofputil_decode_bpf_load_prog(struct ol_bpf_load_prog *,
                                         char **, const struct ofp_header *);
struct ofpbuf *ofputil_encode_bpf_load_prog(enum ofp_version ofp_version,
                                            const ovs_be16 prog_id,
                                            void* program,
                                            const size_t length);

enum ofperr ofputil_decode_bpf_unload_prog(struct ol_bpf_unload_prog *,
                                           const struct ofp_header *);
struct ofpbuf *ofputil_encode_bpf_unload_prog(enum ofp_version ofp_version,
                                              const ovs_be16 prog);

enum ofperr ofputil_decode_bpf_update_map(struct ol_bpf_update_map *msg,
                                          void **data,
                                          const struct ofp_header *oh);
struct ofpbuf *ofputil_encode_bpf_update_map(enum ofp_version ofp_version,
                                             const ovs_be16 prog,
                                             const ovs_be16 map,
                                             void* key, void* value,
                                             const size_t key_size,
                                             const size_t value_size,
                                             const ovs_be32 nb_elems);

enum ofperr
ofputil_decode_dump_map_request(struct ol_bpf_dump_map_request *msg,
                                const ovs_be16 **maps,
                                const struct ofp_header *oh);
struct ofpbuf *
ofputil_encode_dump_map_request(enum ofp_version ofp_version,
                                const ovs_be16 prog,
                                const ovs_be16 nb_maps,
                                const ovs_be16 *maps);
struct ofpbuf *
ofputil_encode_dump_map_reply(struct ol_bpf_dump_map_request *msg,
                              const struct ofp_header *oh,
                              const struct ubpf_map **map,
                              const ovs_be16 *maps,
                              void **data,
                              unsigned int *nb_elems);

struct ofpbuf *
ofputil_encode_bpf_delete_bpf_map(enum ofp_version ofp_version,
                                  const ovs_be16 prog,
                                  const ovs_be16 map,
                                  void *key,
                                  const size_t key_size,
                                  const ovs_be32 nb_elems);

enum ofperr
ofputil_decode_bpf_delete_map(struct ol_bpf_delete_map *msg,
                              const void **keys,
                              const struct ofp_header *oh);

#ifdef __cplusplus
}
#endif

#endif //OVS_OFP_BPF_H
