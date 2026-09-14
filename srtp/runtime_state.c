/* Portable state for execution-owned SRTP contexts. BSD-3-Clause. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "srtp_runtime.h"
#include "stream_list_priv.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(OPENSSL) && defined(GCM) && !defined(NO_64BIT_MATH)
#include <openssl/crypto.h>
#include <openssl/sha.h>

#define HEADER_SIZE 76
#define MAX_INDEX UINT64_C(0xffffffffffff)
struct srtp_runtime_context {
    srtp_t session;
    uint32_t profile, direction, window, extension_count;
    uint8_t key_id[SHA256_DIGEST_LENGTH];
    int dtls;
    uint64_t dtls_used[2];
};
static void put32(uint8_t **p, uint32_t v) {
    (*p)[0] = v >> 24;
    (*p)[1] = v >> 16;
    (*p)[2] = v >> 8;
    (*p)[3] = v;
    *p += 4;
}
static uint32_t get32(const uint8_t **p) {
    uint32_t v = (uint32_t)(*p)[0] << 24 | (uint32_t)(*p)[1] << 16 |
                 (uint32_t)(*p)[2] << 8 | (*p)[3];
    *p += 4;
    return v;
}
static void put64(uint8_t **p, uint64_t v) {
    put32(p, v >> 32);
    put32(p, v);
}
static uint64_t get64(const uint8_t **p) {
    uint64_t hi = get32(p);
    return hi << 32 | get32(p);
}

srtp_err_status_t srtp_runtime_create(const srtp_runtime_options *o,
                                      srtp_runtime_context **out) {
    srtp_runtime_context *c;
    srtp_policy_t p = {0};
    srtp_err_status_t status;
    size_t i, key_length;
    int extensions[255];
    uint8_t key[44];
    if (!out)
        return srtp_err_status_bad_param;
    *out = NULL;
    if (!o || !o->key || o->profile < 1 || o->profile > 3 || o->direction < 1 ||
        o->direction > 3 || o->replay_window < 64 ||
        o->replay_window >= 32768 || o->replay_window % 32 ||
        o->encrypted_extension_count > 255 ||
        (o->encrypted_extension_count && !o->encrypted_extensions))
        return srtp_err_status_bad_param;
    key_length = o->profile == 1 ? 30 : (o->profile == 2 ? 28 : 44);
    if (o->key_length != key_length)
        return srtp_err_status_bad_param;
    for (i = 0; i < o->encrypted_extension_count; i++) {
        uint32_t id = o->encrypted_extensions[i];
        if (!id || id > 255 || (i && id <= o->encrypted_extensions[i - 1]))
            return srtp_err_status_bad_param;
        extensions[i] = (int)id;
    }
    if (o->profile == 1)
        srtp_crypto_policy_set_rtp_default(&p.rtp);
    else if (o->profile == 2)
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&p.rtp);
    else
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&p.rtp);
    p.rtcp = p.rtp;
    p.ssrc.type = o->direction == 1 ? ssrc_any_outbound : ssrc_any_inbound;
    memcpy(key, o->key, key_length);
    p.key = key;
    p.window_size = o->replay_window;
    p.enc_xtn_hdr = extensions;
    p.enc_xtn_hdr_count = (int)o->encrypted_extension_count;
    c = calloc(1, sizeof(*c));
    if (!c) {
        OPENSSL_cleanse(key, sizeof(key));
        return srtp_err_status_alloc_fail;
    }
    status = srtp_create(&c->session, &p);
    OPENSSL_cleanse(key, sizeof(key));
    if (status) {
        free(c);
        return status;
    }
    if (!SHA256(o->key, o->key_length, c->key_id)) {
        srtp_runtime_free(c);
        return srtp_err_status_init_fail;
    }
    if (o->direction == 3)
        c->session->stream_template->direction = dir_unknown;
    c->profile = o->profile;
    c->direction = o->direction;
    c->window = o->replay_window;
    c->extension_count = (uint32_t)o->encrypted_extension_count;
    *out = c;
    return srtp_err_status_ok;
}
srtp_err_status_t srtp_runtime_create_dtls(const srtp_runtime_options *options,
                                           srtp_runtime_context **out) {
    if (!out) return srtp_err_status_bad_param;
    *out = NULL;
    if (!options || options->direction == 3) return srtp_err_status_bad_param;
    srtp_err_status_t status = srtp_runtime_create(options, out);
    if (!status) (*out)->dtls = 1;
    return status;
}
void srtp_runtime_free(srtp_runtime_context *c) {
    if (!c)
        return;
    srtp_dealloc(c->session);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}
struct stream_array {
    size_t count;
    srtp_stream_t *streams;
};
static int count_stream(srtp_stream_t stream, void *data) {
    struct stream_array *a = data;
    (void)stream;
    if (a->count == UINT32_MAX)
        return 1;
    a->count++;
    return 0;
}
static int collect_stream(srtp_stream_t stream, void *data) {
    struct stream_array *a = data;
    a->streams[a->count++] = stream;
    return 0;
}
static int compare_stream(const void *a, const void *b) {
    uint32_t x = ntohl((*(const srtp_stream_t *)a)->ssrc);
    uint32_t y = ntohl((*(const srtp_stream_t *)b)->ssrc);
    return (x > y) - (x < y);
}
srtp_err_status_t srtp_runtime_export(srtp_runtime_context *c, uint8_t *output,
                                      size_t *length) {
    struct stream_array a = {0};
    size_t needed, record, i, j;
    uint8_t *p = output;
    srtp_stream_t t;
    if (!c || !length || c->dtls)
        return srtp_err_status_bad_param;
    t = c->session->stream_template;
    srtp_stream_list_for_each(c->session->stream_list, count_stream, &a);
    record = 40 + c->window / 8;
    needed = HEADER_SIZE + 4 * c->extension_count;
    if (a.count > (SIZE_MAX - needed) / record ||
        a.count > SIZE_MAX / sizeof(srtp_stream_t))
        return srtp_err_status_alloc_fail;
    needed += a.count * record;
    if (!output) {
        *length = needed;
        return srtp_err_status_ok;
    }
    if (*length < needed) {
        *length = needed;
        return srtp_err_status_bad_param;
    }
    if (a.count) {
        a.streams = malloc(a.count * sizeof(srtp_stream_t));
        if (!a.streams)
            return srtp_err_status_alloc_fail;
        a.count = 0;
        srtp_stream_list_for_each(c->session->stream_list, collect_stream, &a);
        qsort(a.streams, a.count, sizeof(srtp_stream_t), compare_stream);
    }
    memcpy(p, "IMSRTP01", 8);
    p += 8;
    put32(&p, 1);
    put32(&p, c->profile);
    put32(&p, c->direction);
    put32(&p, c->window);
    put32(&p, c->extension_count);
    put32(&p, (uint32_t)a.count);
    memcpy(p, c->key_id, sizeof(c->key_id));
    p += sizeof(c->key_id);
    put64(&p, t->session_keys[0].limit->num_left);
    put32(&p, t->session_keys[0].limit->state);
    for (i = 0; i < c->extension_count; i++)
        put32(&p, t->enc_xtn_hdr[i]);
    for (i = 0; i < a.count; i++) {
        srtp_stream_t s = a.streams[i];
        put32(&p, ntohl(s->ssrc));
        put64(&p, s->rtp_rdbx.index);
        put32(&p, s->pending_roc);
        put32(&p, s->rtcp_rdb.window_start);
        put32(&p, s->direction);
        for (j = 0; j < 4; j++)
            put32(&p, s->rtcp_rdb.bitmask.v32[j]);
        for (j = 0; j < c->window / 32; j++)
            put32(&p, s->rtp_rdbx.bitmask.word[j]);
    }
    free(a.streams);
    *length = needed;
    return srtp_err_status_ok;
}
srtp_err_status_t srtp_runtime_restore(const srtp_runtime_options *o,
                                       const uint8_t *blob, size_t length,
                                       srtp_runtime_context **out) {
    srtp_runtime_context *c = NULL;
    const uint8_t *p = blob;
    uint32_t count, state, previous = 0;
    uint64_t remaining;
    size_t record, expected, i, j;
    srtp_err_status_t status;
    if (!out)
        return srtp_err_status_bad_param;
    *out = NULL;
    if (!blob || length < HEADER_SIZE || memcmp(blob, "IMSRTP01", 8))
        return srtp_err_status_bad_param;
    status = srtp_runtime_create(o, &c);
    if (status)
        return status;
    p += 8;
    if (get32(&p) != 1 || get32(&p) != c->profile ||
        get32(&p) != c->direction || get32(&p) != c->window ||
        get32(&p) != c->extension_count)
        goto invalid;
    count = get32(&p);
    if (CRYPTO_memcmp(p, c->key_id, sizeof(c->key_id)))
        goto invalid;
    p += sizeof(c->key_id);
    remaining = get64(&p);
    state = get32(&p);
    if (remaining > MAX_INDEX || state > srtp_key_state_expired ||
        (state == srtp_key_state_normal && remaining < 0x10000) ||
        (state == srtp_key_state_past_soft_limit &&
         (!remaining || remaining >= 0x10000)) ||
        (state == srtp_key_state_expired && remaining != 0))
        goto invalid;
    record = 40 + c->window / 8;
    expected = HEADER_SIZE + 4 * c->extension_count;
    if (count > (SIZE_MAX - expected) / record ||
        length != expected + count * record)
        goto invalid;
    for (i = 0; i < c->extension_count; i++)
        if (get32(&p) != o->encrypted_extensions[i])
            goto invalid;
    c->session->stream_template->session_keys[0].limit->num_left = remaining;
    c->session->stream_template->session_keys[0].limit->state =
        (srtp_key_state_t)state;
    for (i = 0; i < count; i++) {
        uint32_t ssrc = get32(&p);
        srtp_stream_t s;
        if (i && ssrc <= previous)
            goto invalid;
        previous = ssrc;
        status = srtp_runtime_clone_stream(c->session, htonl(ssrc), &s);
        if (status) {
            srtp_runtime_free(c);
            return status;
        }
        s->rtp_rdbx.index = get64(&p);
        s->pending_roc = get32(&p);
        s->rtcp_rdb.window_start = get32(&p);
        uint32_t stream_direction = get32(&p);
        if (stream_direction < 1 || stream_direction > 2 ||
            (c->direction != 3 && stream_direction != c->direction) ||
            s->rtp_rdbx.index > MAX_INDEX || s->pending_roc != 0 ||
            s->rtcp_rdb.window_start > 0x7fffffff)
            goto invalid;
        s->direction = (direction_t)stream_direction;
        for (j = 0; j < 4; j++)
            s->rtcp_rdb.bitmask.v32[j] = get32(&p);
        for (j = 0; j < c->window / 32; j++)
            s->rtp_rdbx.bitmask.word[j] = get32(&p);
        /* A zero bitmap/index can mean only SRTCP has used this SSRC.
         * For initial ROC, no bits may refer to a negative packet index. */
        for (j = 0; j < c->window; j++)
            if (c->window - 1 - j > s->rtp_rdbx.index &&
                bitvector_get_bit(&s->rtp_rdbx.bitmask, j))
                goto invalid;
        for (j = 0; j < 128; j++)
            if (v128_get_bit(&s->rtcp_rdb.bitmask, j) &&
                (s->direction == dir_srtp_sender ||
                 (uint64_t)s->rtcp_rdb.window_start + j > 0x7fffffff))
                goto invalid;
    }
    *out = c;
    return srtp_err_status_ok;
invalid:
    srtp_runtime_free(c);
    return srtp_err_status_bad_param;
}
srtp_err_status_t srtp_runtime_packet(srtp_runtime_context *c, int sending,
                                      int rtcp, uint8_t *packet,
                                      size_t capacity, size_t *length) {
    srtp_err_status_t status;
    int n;
    uint32_t trailer;
    if (!c || !packet || !length || *length > capacity || *length > INT_MAX ||
        (rtcp != 0 && rtcp != 1))
        return srtp_err_status_bad_param;
    if ((sending != 0 && sending != 1) || (c->direction == 1 && !sending) ||
        (c->direction == 2 && sending) || *length < (rtcp ? 8u : 12u))
        return srtp_err_status_bad_param;
    /* RFC 5764 section 4.1.2 / RFC 7714 section 14.2. Separate derivation
     * labels give RTP and SRTCP separate limits, shared across every SSRC. */
    if (c->dtls && c->dtls_used[rtcp] >=
        (UINT64_C(1) << (rtcp || c->profile == 1 ? 31 : 48)))
        return srtp_err_status_key_expired;
    uint32_t ssrc;
    memcpy(&ssrc, packet + (rtcp ? 4 : 8), sizeof(ssrc));
    srtp_stream_t stream = srtp_stream_list_get(c->session->stream_list, ssrc);
    if (stream &&
        stream->direction != (sending ? dir_srtp_sender : dir_srtp_receiver))
        return srtp_err_status_bad_param;
    n = (int)*length;
    if (sending) {
        status =
            rtcp ? srtp_get_protect_rtcp_trailer_length(c->session, 0, 0,
                                                        &trailer)
                 : srtp_get_protect_trailer_length(c->session, 0, 0, &trailer);
        if (status)
            return status;
        if (trailer > capacity - *length || *length > INT_MAX - trailer)
            return srtp_err_status_bad_param;
        status = rtcp ? srtp_protect_rtcp(c->session, packet, &n)
                      : srtp_protect(c->session, packet, &n);
    } else {
        status = rtcp ? srtp_unprotect_rtcp(c->session, packet, &n)
                      : srtp_unprotect(c->session, packet, &n);
    }
    if (c->direction == 3)
        c->session->stream_template->direction = dir_unknown;
    if (!status) {
        *length = (size_t)n;
        if (c->dtls) c->dtls_used[rtcp]++;
    }
    return status;
}
#else
/* The private product build selects OpenSSL + GCM and native uint64_t. */
srtp_err_status_t srtp_runtime_create(const srtp_runtime_options *o,
                                      srtp_runtime_context **c) {
    (void)o;
    if (c)
        *c = NULL;
    return srtp_err_status_no_such_op;
}
srtp_err_status_t srtp_runtime_create_dtls(const srtp_runtime_options *o,
                                           srtp_runtime_context **c) {
    return srtp_runtime_create(o, c);
}
srtp_err_status_t srtp_runtime_restore(const srtp_runtime_options *o,
                                       const uint8_t *b, size_t n,
                                       srtp_runtime_context **c) {
    (void)b;
    (void)n;
    return srtp_runtime_create(o, c);
}
srtp_err_status_t srtp_runtime_export(srtp_runtime_context *c, uint8_t *b,
                                      size_t *n) {
    (void)c;
    (void)b;
    (void)n;
    return srtp_err_status_no_such_op;
}
void srtp_runtime_free(srtp_runtime_context *c) { (void)c; }
srtp_err_status_t srtp_runtime_packet(srtp_runtime_context *c, int sending,
                                      int r, uint8_t *b, size_t cap,
                                      size_t *n) {
    (void)c;
    (void)sending;
    (void)r;
    (void)b;
    (void)cap;
    (void)n;
    return srtp_err_status_no_such_op;
}
#endif
