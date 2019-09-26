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
#include "bpf/ubpf_int.h"


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

enum ofperr ofputil_decode_bpf_unload_prog(struct ol_bpf_unload_prog *msg,
                                           const struct ofp_header *oh)
{
    enum ofperr error = 0;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw != OFPRAW_NXT_BPF_UNLOAD_PROG) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    struct ol_bpf_unload_prog *buffer;
    buffer = ofpbuf_pull(&b, sizeof *buffer);

    msg->prog = ntohs(buffer->prog);

    return error;
}

struct ofpbuf *ofputil_encode_bpf_unload_prog(enum ofp_version ofp_version,
                                              const ovs_be16 prog)
{
    struct ofpbuf *request;
    struct ol_bpf_unload_prog *msg;

    request = ofpraw_alloc(OFPRAW_NXT_BPF_UNLOAD_PROG, ofp_version, 0);
    ofpbuf_put_zeros(request, sizeof *msg);
    msg = request->msg;
    msg->prog = htons(prog);

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

enum ofperr
ofputil_decode_bpf_dump_map_request(struct ol_bpf_dump_map_request *msg,
                                const ovs_be16 **maps,
                                const struct ofp_header *oh)
{
    enum ofperr error = 0;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw != OFPRAW_NXT_BPF_DUMP_MAP_REQUEST) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    struct ol_bpf_dump_map_request *buffer = ofpbuf_pull(&b,
                                                     sizeof(struct ol_bpf_dump_map_request));

    msg->prog = ntohs(buffer->prog);
    msg->nb_maps = ntohs(buffer->nb_maps);

    if(!msg->prog) {
        VLOG_WARN_RL(&rl,
                     "The filter program identifier is not provided.");
        return OFPERR_OFPBRC_EPERM;
    }

    size_t maps_size = (size_t)(sizeof(**maps) * msg->nb_maps);
    *maps = ofpbuf_try_pull(&b, maps_size);
    if (!*maps) {
        VLOG_WARN_RL(&rl, "size of provided map identifiers array is incorrect"
                                    " (%"PRIu32")", maps_size);
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return error;
}

struct ofpbuf *
ofputil_encode_bpf_dump_map_request(enum ofp_version ofp_version,
                                const ovs_be16 prog,
                                const ovs_be16 nb_maps,
                                const ovs_be16 *maps)
{
    struct ofpbuf *request;
    struct ol_bpf_dump_map_request *msg;
    size_t maps_size = (size_t)(sizeof(*maps) * nb_maps);

    request = ofpraw_alloc(OFPRAW_NXT_BPF_DUMP_MAP_REQUEST, ofp_version, maps_size);
    ofpbuf_put_zeros(request, sizeof *msg);

    msg = request->msg;
    msg->prog = htons(prog);
    msg->nb_maps = htons(nb_maps);

    ofpbuf_put(request, maps, maps_size);

    ofpmsg_update_length(request);

    return request;
}

struct ofpbuf *
ofputil_encode_bpf_dump_map_reply(struct ol_bpf_dump_map_request *msg,
                              const struct ofp_header *oh,
                              const struct ubpf_map **map,
                              const ovs_be16 *maps,
                              void **data,
                              unsigned int *nb_elems)
{
    struct ofpbuf *output_buffer;
    struct ol_bpf_dump_map_reply *dump_map_reply;

    size_t all_maps_size = 0;
    for(int i = 0; i < msg->nb_maps; i++) {
        all_maps_size += sizeof(struct ol_bpf_dump_map);
        all_maps_size += (size_t) (nb_elems[i] * (map[i]->key_size + map[i]->value_size));
    }

    output_buffer = ofpraw_alloc_reply(OFPRAW_NXT_BPF_DUMP_MAP_REPLY, oh,
                                       all_maps_size);
    ofpbuf_put_zeros(output_buffer, sizeof(struct ol_bpf_dump_map_reply));
    dump_map_reply = output_buffer->msg;
    dump_map_reply->prog = msg->prog;
    dump_map_reply->nb_maps = msg->nb_maps;

    for(int i = 0; i < msg->nb_maps; i++) {
        struct ol_bpf_dump_map *dump_map = data[i];
        size_t map_data_size = (size_t) (nb_elems[i] * (map[i]->key_size + map[i]->value_size));

        dump_map->map = maps[i];
        dump_map->key_size = map[i]->key_size;
        dump_map->value_size = map[i]->value_size;
        dump_map->nb_elems = nb_elems[i];

        ofpbuf_put(output_buffer, data[i], sizeof(*dump_map) + map_data_size);
    }

    ofpmsg_update_length(output_buffer);

    return output_buffer;
}

struct ofpbuf *
ofputil_encode_bpf_delete_bpf_map(enum ofp_version ofp_version,
                                  const ovs_be16 prog,
                                  const ovs_be16 map,
                                  void *key,
                                  const size_t key_size,
                                  const ovs_be32 nb_elems)
{
    struct ofpbuf *request;
    struct ol_bpf_delete_map *msg;

    size_t length = (size_t) (nb_elems * key_size);

    request = ofpraw_alloc(OFPRAW_NXT_BPF_DELETE_MAP, ofp_version, length);
    ofpbuf_put_zeros(request, sizeof *msg);

    msg = request->msg;
    msg->prog = htons(prog);
    msg->map = htons(map);
    msg->key_size = htonl(key_size);
    msg->nb_elems = htonl(nb_elems);

    ofpbuf_put(request, key, key_size);

    ofpmsg_update_length(request);

    return request;
}

enum ofperr
ofputil_decode_bpf_delete_map(struct ol_bpf_delete_map *msg,
                              const void **keys,
                              const struct ofp_header *oh)
{
    enum ofperr error = 0;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofpraw raw = ofpraw_pull_assert(&b);
    if (raw != OFPRAW_NXT_BPF_DELETE_MAP) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    struct ol_bpf_delete_map *buffer = ofpbuf_pull(&b,
                                                   sizeof(struct ol_bpf_delete_map));

    msg->prog = ntohs(buffer->prog);
    msg->map = ntohs(buffer->map);
    msg->key_size = ntohl(buffer->key_size);
    msg->nb_elems = ntohl(buffer->nb_elems);

    if(!msg->prog) {
        VLOG_WARN_RL(&rl,
                     "The program identifier is not provided.");
        return OFPERR_OFPBRC_EPERM;
    }

    size_t data_size = (size_t) (msg->nb_elems * msg->key_size);

    *keys = ofpbuf_try_pull(&b, data_size);
    if (!*keys) {
        VLOG_WARN_RL(&rl, "Size of provided map keys is incorrect (%"PRIu32")",
                data_size);

        return OFPERR_OFPBMC_BAD_LEN;
    }

    return error;
}



