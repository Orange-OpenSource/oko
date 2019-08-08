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
//        VLOG_WARN_RL(&rl, "size of BPF program is incorrect"
//                                    " (%"PRIu32")", msg->file_len);
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



