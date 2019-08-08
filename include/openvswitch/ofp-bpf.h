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

#ifdef __cplusplus
}
#endif

#endif //OVS_OFP_BPF_H
