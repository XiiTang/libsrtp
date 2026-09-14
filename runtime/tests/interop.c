/* Compile twice: one executable against the runtime fork and one against an
 * unmodified libSRTP. Only framed wire packets cross the process boundary. */
#include "srtp.h"
#ifdef RUNTIME_PEER
#include "srtp_runtime.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void put32(unsigned char *p, unsigned n) {
    p[0] = n >> 24;
    p[1] = n >> 16;
    p[2] = n >> 8;
    p[3] = n;
}
int main(int argc, char **argv) {
    unsigned char key[44], b[256], plain[256], header[4];
    unsigned profile, sending, i, r, ssrc, seq;
    int n, expected;
#ifdef RUNTIME_PEER
    srtp_runtime_context *c, *restored;
    srtp_runtime_options o = {0};
#else
    srtp_t c;
    srtp_policy_t p = {0};
#endif
    assert(argc == 3);
    profile = (unsigned)atoi(argv[1]);
    sending = (unsigned)atoi(argv[2]);
    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    assert(srtp_init() == 0);
#ifdef RUNTIME_PEER
    o.profile = profile;
    o.direction = sending ? 1 : 2;
    o.key = key;
    o.key_length = profile == 1 ? 30 : (profile == 2 ? 28 : 44);
    o.replay_window = 128;
    assert(srtp_runtime_create(&o, &c) == 0);
#else
    if (profile == 1)
        srtp_crypto_policy_set_rtp_default(&p.rtp);
    else if (profile == 2)
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&p.rtp);
    else
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&p.rtp);
    p.rtcp = p.rtp;
    p.ssrc.type = sending ? ssrc_any_outbound : ssrc_any_inbound;
    p.key = key;
    p.window_size = 128;
    assert(srtp_create(&c, &p) == 0);
#endif
    for (i = 0; i < 400; i++) {
        r = i % 2;
        ssrc = 1 + (i / 2) % 2;
        seq = (65534 + i / 4) & 65535;
        memset(plain, 0, sizeof(plain));
        plain[0] = 0x80;
        if (r) {
            plain[1] = 201;
            plain[3] = 1;
            put32(plain + 4, ssrc);
            expected = 8;
        } else {
            plain[1] = 96;
            plain[2] = seq >> 8;
            plain[3] = seq;
            put32(plain + 4, seq * 160);
            put32(plain + 8, ssrc);
            memset(plain + 12, (int)(i & 255), 17);
            expected = 29;
        }
        if (sending) {
            memcpy(b, plain, (size_t)expected);
            n = expected;
        } else {
            assert(fread(header, 1, 4, stdin) == 4);
            n = header[2] * 256 + header[3];
            assert(n > 0 && n < 256);
            assert(fread(b, 1, (size_t)n, stdin) == (size_t)n);
        }
#ifdef RUNTIME_PEER
        {
            size_t length = (size_t)n, state_length = 0;
            unsigned char *state;
            assert(srtp_runtime_packet(c, (int)sending, (int)r, b, sizeof(b),
                                       &length) == 0);
            n = (int)length;
            assert(srtp_runtime_export(c, NULL, &state_length) == 0);
            state = malloc(state_length);
            assert(state);
            assert(srtp_runtime_export(c, state, &state_length) == 0);
            assert(srtp_runtime_restore(&o, state, state_length, &restored) ==
                   0);
            free(state);
            srtp_runtime_free(c);
            c = restored;
        }
#else
        assert((sending
                    ? (r ? srtp_protect_rtcp(c, b, &n) : srtp_protect(c, b, &n))
                    : (r ? srtp_unprotect_rtcp(c, b, &n)
                         : srtp_unprotect(c, b, &n))) == 0);
#endif
        if (sending) {
            put32(header, (unsigned)n);
            assert(fwrite(header, 1, 4, stdout) == 4);
            assert(fwrite(b, 1, (size_t)n, stdout) == (size_t)n);
        } else
            assert(n == expected && !memcmp(b, plain, (size_t)n));
    }
    if (!sending)
        assert(fgetc(stdin) == EOF);
#ifdef RUNTIME_PEER
    srtp_runtime_free(c);
#else
    assert(srtp_dealloc(c) == 0);
#endif
    assert(srtp_shutdown() == 0);
    return 0;
}
