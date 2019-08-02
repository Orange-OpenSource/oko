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

#include <config.h>
#include <inttypes.h>
#include "openvswitch/ofp-bpf.h"
#include "openflow/orange-ext.h"
#include <errno.h>
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_bpf);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

enum ofperr
ofputil_decode_bpf_load_prog(struct ol_bpf_load_prog *msg,
                             char **elf_file, const struct ofp_header *oh)
{
    enum ofperr error = 0;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw != OFPRAW_NXT_BPF_LOAD_PROG) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    struct ol_bpf_load_prog *buffer = ofpbuf_pull(&b, sizeof buffer);

    if (!buffer->file_len) {
        VLOG_WARN_RL(&rl, "size of BPF program is null");
        return OFPERR_OFPBMC_BAD_LEN;
    }

    msg->prog_id = ntohs(buffer->prog_id);
    msg->file_len = ntohl(buffer->file_len);

    *elf_file = ofpbuf_try_pull(&b, msg->file_len);
    if (!*elf_file) {
        VLOG_WARN_RL(&rl, "size of BPF program is incorrect (%"PRIu32")",
                     msg->file_len);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return error;
}

struct ofpbuf *ofputil_encode_bpf_load_prog(enum ofp_version ofp_version,
                                            const ovs_be16 prog_id,
                                            void* program,
                                            const size_t length)
{
    struct ofpbuf *request;
    struct ol_bpf_load_prog *msg;

    request = ofpraw_alloc(OFPRAW_NXT_BPF_LOAD_PROG, ofp_version, length);
    ofpbuf_put_zeros(request, sizeof *msg);
    msg = request->msg;
    msg->prog_id = htons(prog_id);
    msg->file_len = htonl(length);
    ofpbuf_put(request, program, length);

    return request;
}

enum ofperr
ofputil_decode_bpf_update_map(struct ol_bpf_update_map *msg,
                              void **data, const struct ofp_header *oh)
{
    enum ofperr error = 0;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw != OFPRAW_NXT_BPF_UPDATE_MAP) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    struct ol_bpf_update_map *buffer = ofpbuf_pull(&b,
            sizeof(struct ol_bpf_update_map));

    msg->prog_id = ntohs(buffer->prog_id);
    msg->map_id = ntohs(buffer->map_id);
    msg->key_size = ntohl(buffer->key_size);
    msg->value_size = ntohl(buffer->value_size);
    msg->nb_elems = ntohl(buffer->nb_elems);

    if(!msg->prog_id) {
        VLOG_WARN_RL(&rl,
                     "The filter program identifier is not provided.");
        return OFPERR_OFPBRC_EPERM;
    }

    size_t data_size =
            (size_t) (msg->nb_elems * (msg->key_size + msg->value_size));
    *data = ofpbuf_try_pull(&b, data_size);
    if (!*data) {
        VLOG_WARN_RL(&rl, "Size of provided map tuples is incorrect (%"PRIu32")",
                     data_size);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return error;
}

struct ofpbuf *
ofputil_encode_bpf_update_map(enum ofp_version ofp_version,
                              const ovs_be16 prog, const ovs_be16 map,
                              void* key, void* value,
                              const size_t key_size,
                              const size_t value_size,
                              const ovs_be32 nb_elems)
{
    struct ofpbuf *request;
    struct ol_bpf_update_map *msg;

    if (nb_elems != 1) {
        return NULL;
    }

    size_t length = (size_t) (nb_elems * (key_size + value_size));

    request = ofpraw_alloc(OFPRAW_NXT_BPF_UPDATE_MAP, ofp_version, length);

    ofpbuf_put_zeros(request, sizeof *msg);

    msg = request->msg;
    msg->prog_id = htons(prog);
    msg->map_id = htons(map);
    msg->key_size = htonl(key_size);
    msg->value_size = htonl(value_size);
    msg->nb_elems = htonl(nb_elems);

    ofpbuf_put(request, key, key_size);
    ofpbuf_put(request, value, value_size);

    ofpmsg_update_length(request);

    return request;
}



