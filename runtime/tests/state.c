/* Runtime-state contract tests; BSD-3-Clause. */
#include "srtp_runtime.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OK(call)                                                               \
    do {                                                                       \
        srtp_err_status_t result_ = (call);                                    \
        if (result_) {                                                         \
            fprintf(stderr, "%s:%d %s returned %d\n", __FILE__, __LINE__,      \
                    #call, result_);                                           \
            abort();                                                           \
        }                                                                      \
    } while (0)
static uint8_t key[44];
static const uint32_t extensions[] = {1, 3, 15};
static srtp_runtime_options options(uint32_t profile, uint32_t direction) {
    srtp_runtime_options o = {
        profile, direction,  key, profile == 1 ? 30 : (profile == 2 ? 28 : 44),
        128,     extensions, 3};
    return o;
}
static void u32(uint8_t *p, uint32_t n) {
    p[0] = n >> 24;
    p[1] = n >> 16;
    p[2] = n >> 8;
    p[3] = n;
}
static size_t packet(uint8_t *p, int rtcp, uint32_t ssrc, uint16_t seq) {
    memset(p, 0, 128);
    p[0] = 0x80;
    if (rtcp) {
        p[1] = 201;
        p[3] = 1;
        u32(p + 4, ssrc);
        return 8;
    }
    p[1] = 96;
    p[2] = seq >> 8;
    p[3] = seq;
    u32(p + 4, seq * 160);
    u32(p + 8, ssrc);
    memcpy(p + 12, "binary\0payload\xff", 15);
    return 27;
}
static uint8_t *save(srtp_runtime_context *c, size_t *size) {
    uint8_t *b;
    *size = 0;
    OK(srtp_runtime_export(c, NULL, size));
    b = malloc(*size);
    assert(b);
    OK(srtp_runtime_export(c, b, size));
    return b;
}
static srtp_runtime_context *clone(srtp_runtime_context *c,
                                   srtp_runtime_options *o) {
    size_t n;
    uint8_t *b = save(c, &n), *again;
    srtp_runtime_context *copy = NULL;
    OK(srtp_runtime_restore(o, b, n, &copy));
    again = save(copy, &n);
    assert(!memcmp(b, again, n));
    free(again);
    free(b);
    return copy;
}
static void exercise(uint32_t profile) {
    srtp_runtime_options txo = options(profile, 1), rxo = options(profile, 2);
    srtp_runtime_context *tx, *rx, *tx2, *rx2;
    uint8_t a[128], b[128], plain[128], replay[2][128];
    size_t an, bn, pn, replay_n[2];
    uint32_t ssrc;
    int rtcp;
    unsigned seq;
    OK(srtp_runtime_create(&txo, &tx));
    OK(srtp_runtime_create(&rxo, &rx));
    for (ssrc = 1; ssrc <= 4; ssrc++) {
        for (rtcp = 0; rtcp <= 1; rtcp++) {
            pn = an = packet(a, rtcp, ssrc, 65535);
            memcpy(plain, a, pn);
            OK(srtp_runtime_packet(tx, 1, rtcp, a, sizeof(a), &an));
            if (ssrc == 1) {
                memcpy(replay[rtcp], a, an);
                replay_n[rtcp] = an;
            }
            OK(srtp_runtime_packet(rx, 0, rtcp, a, sizeof(a), &an));
            assert(an == pn && !memcmp(a, plain, pn));
        }
    }
    tx2 = clone(tx, &txo);
    rx2 = clone(rx, &rxo);
    for (rtcp = 0; rtcp <= 1; rtcp++) {
        an = replay_n[rtcp];
        memcpy(a, replay[rtcp], an);
        assert(srtp_runtime_packet(rx2, 0, rtcp, a, sizeof(a), &an) ==
               srtp_err_status_replay_fail);
    }
    /* Sequence rollover, reordered SSRCs, and future SRTCP indices must be
     * byte-identical to the uninterrupted context. */
    for (seq = 0; seq < 180; seq++) {
        for (ssrc = 6; ssrc >= 1; ssrc--) {
            for (rtcp = 0; rtcp <= 1; rtcp++) {
                pn = an = bn = packet(a, rtcp, ssrc, (uint16_t)seq);
                memcpy(b, a, an);
                memcpy(plain, a, an);
                OK(srtp_runtime_packet(tx, 1, rtcp, a, sizeof(a), &an));
                OK(srtp_runtime_packet(tx2, 1, rtcp, b, sizeof(b), &bn));
                assert(an == bn && !memcmp(a, b, an));
                OK(srtp_runtime_packet(rx, 0, rtcp, a, sizeof(a), &an));
                OK(srtp_runtime_packet(rx2, 0, rtcp, b, sizeof(b), &bn));
                assert(an == pn && bn == pn && !memcmp(a, plain, pn) &&
                       !memcmp(b, plain, pn));
            }
        }
    }
    /* Reopen after the replay window has shifted as well. */
    srtp_runtime_free(tx2);
    srtp_runtime_free(rx2);
    tx2 = clone(tx, &txo);
    rx2 = clone(rx, &rxo);
    an = packet(a, 0, 1, 179);
    assert(srtp_runtime_packet(tx2, 1, 0, a, sizeof(a), &an) ==
           srtp_err_status_replay_fail);
    for (rtcp = 0; rtcp <= 1; rtcp++) {
        an = replay_n[rtcp];
        memcpy(a, replay[rtcp], an);
        assert(srtp_runtime_packet(rx2, 0, rtcp, a, sizeof(a), &an) ==
               srtp_err_status_replay_old);
    }
    srtp_runtime_free(tx);
    srtp_runtime_free(rx);
    srtp_runtime_free(tx2);
    srtp_runtime_free(rx2);
}
static void reject(srtp_runtime_options *o, uint8_t *blob, size_t n) {
    srtp_runtime_context *out = (srtp_runtime_context *)(void *)blob;
    assert(srtp_runtime_restore(o, blob, n, &out) != srtp_err_status_ok);
    assert(out == NULL);
}
static void malformed(void) {
    srtp_runtime_options o = options(1, 1), wrong;
    srtp_runtime_context *c, *expired;
    uint8_t a[128], *blob, *bad;
    size_t n, an, i;
    OK(srtp_runtime_create(&o, &c));
    an = packet(a, 0, 1, 10);
    OK(srtp_runtime_packet(c, 1, 0, a, sizeof(a), &an));
    an = packet(a, 0, 2, 10);
    OK(srtp_runtime_packet(c, 1, 0, a, sizeof(a), &an));
    blob = save(c, &n);
    bad = malloc(n + 1);
    assert(bad);
    for (i = 0; i < n; i++)
        reject(&o, blob, i);
    memcpy(bad, blob, n);
    bad[n] = 0;
    reject(&o, bad, n + 1);
    for (i = 0; i < 64; i++) {
        memcpy(bad, blob, n);
        bad[i] ^= 0x80;
        reject(&o, bad, n);
    }
    wrong = o;
    wrong.direction = 2;
    reject(&wrong, blob, n);
    wrong = o;
    wrong.replay_window = 256;
    reject(&wrong, blob, n);
    wrong = o;
    wrong.encrypted_extension_count = 0;
    reject(&wrong, blob, n);
    key[0] ^= 1;
    reject(&o, blob, n);
    key[0] ^= 1;
    /* Duplicate SSRC, impossible index, nonzero pending ROC and negative-index
     * replay bit. */
    memcpy(bad, blob, n);
    memcpy(bad + 88 + 56, bad + 88, 4);
    reject(&o, bad, n);
    memcpy(bad, blob, n);
    bad[92] = 1;
    reject(&o, bad, n);
    memcpy(bad, blob, n);
    bad[103] = 1;
    reject(&o, bad, n);
    memcpy(bad, blob, n);
    bad[131] |= 1;
    reject(&o, bad, n);
    /* Shared key exhaustion must remain terminal across repeated use and
     * restore, including a new SSRC (clones share the same usage limit). */
    memcpy(bad, blob, n);
    memset(bad + 64, 0, 8);
    u32(bad + 72, 2);
    OK(srtp_runtime_restore(&o, bad, n, &expired));
    for (i = 0; i < 3; i++) {
        an = packet(a, 0, (uint32_t)(i + 1), 11);
        assert(srtp_runtime_packet(expired, 1, 0, a, sizeof(a), &an) ==
               srtp_err_status_key_expired);
    }
    srtp_runtime_free(c);
    c = clone(expired, &o);
    an = packet(a, 0, 9, 12);
    assert(srtp_runtime_packet(c, 1, 0, a, sizeof(a), &an) ==
           srtp_err_status_key_expired);
    srtp_runtime_free(c);
    srtp_runtime_free(expired);
    /* Final ROC cannot roll over to zero even with packet uses remaining. */
    memcpy(bad, blob, n);
    memset(bad + 92, 0, 2);
    memset(bad + 94, 255, 6);
    OK(srtp_runtime_restore(&o, bad, n, &c));
    an = packet(a, 0, 1, 0);
    assert(srtp_runtime_packet(c, 1, 0, a, sizeof(a), &an) ==
           srtp_err_status_key_expired);
    srtp_runtime_free(c);
    free(blob);
    free(bad);
}
static void duplex(void) {
    for (uint32_t profile = 1; profile <= 3; profile++) {
        srtp_runtime_options o = options(profile, 3);
        srtp_runtime_context *a, *b, *copy;
        uint8_t packet_bytes[128], original[128];
        size_t n, plain;
        OK(srtp_runtime_create(&o, &a));
        OK(srtp_runtime_create(&o, &b));
        for (unsigned seq = 65534; seq < 65538; seq++) {
            for (int rtcp = 0; rtcp <= 1; rtcp++) {
                for (int direction = 0; direction <= 1; direction++) {
                    srtp_runtime_context *sender = direction ? a : b;
                    srtp_runtime_context *receiver = direction ? b : a;
                    plain = n = packet(packet_bytes, rtcp, direction ? 7 : 8,
                                       (uint16_t)seq);
                    memcpy(original, packet_bytes, n);
                    OK(srtp_runtime_packet(sender, 1, rtcp, packet_bytes,
                                           sizeof(packet_bytes), &n));
                    OK(srtp_runtime_packet(receiver, 0, rtcp, packet_bytes,
                                           sizeof(packet_bytes), &n));
                    assert(n == plain && !memcmp(original, packet_bytes, n));
                }
            }
            copy = clone(a, &o);
            srtp_runtime_free(a);
            a = copy;
            copy = clone(b, &o);
            srtp_runtime_free(b);
            b = copy;
        }
        /* Same actual key may be bidirectional, but an SSRC cannot switch
         * direction and reuse an existing key/index pair. */
        n = packet(packet_bytes, 0, 8, 20);
        assert(srtp_runtime_packet(a, 1, 0, packet_bytes, sizeof(packet_bytes),
                                   &n) == srtp_err_status_bad_param);
        n = packet(packet_bytes, 0, 7, 20);
        assert(srtp_runtime_packet(a, 0, 0, packet_bytes, sizeof(packet_bytes),
                                   &n) == srtp_err_status_bad_param);
        srtp_runtime_free(a);
        srtp_runtime_free(b);
    }
}
int main(void) {
    size_t i;
    for (i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    OK(srtp_init());
    exercise(1);
    exercise(2);
    exercise(3);
    malformed();
    duplex();
    OK(srtp_shutdown());
    puts("SRTP state: all profiles, rollover, multi-SSRC, RTP/SRTCP replay, "
         "malformed state, key exhaustion passed");
    return 0;
}
