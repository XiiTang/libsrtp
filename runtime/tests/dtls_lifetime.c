/* Include the exact native implementation to inject near-limit counters without
 * billions of packets or a production test hook. Public packet processing and
 * native crypto remain unchanged. This executable owns these API definitions. */
#include "../../srtp/runtime_state.c"
#include <assert.h>
#include <stdio.h>
int main(void) {
    assert(srtp_init() == 0);
    uint8_t key[44] = {0};
    for (uint32_t profile = 1; profile <= 3; profile++) {
        srtp_runtime_options o = {profile, 1, key, profile == 1 ? 30 : profile == 2 ? 28 : 44, 128, NULL, 0};
        srtp_runtime_context *tx, *rx;
        assert(srtp_runtime_create_dtls(&o, &tx) == 0);
        o.direction = 2; assert(srtp_runtime_create_dtls(&o, &rx) == 0);
        size_t n = 0; assert(srtp_runtime_export(tx, NULL, &n) == srtp_err_status_bad_param);
        for (int rtcp = 0; rtcp <= 1; rtcp++) {
            uint64_t maximum = UINT64_C(1) << (rtcp || profile == 1 ? 31 : 48);
            tx->dtls_used[rtcp] = rx->dtls_used[rtcp] = maximum - 1;
            uint8_t bytes[128] = {128, rtcp ? 201 : 96, 0, rtcp ? 1 : 0, 0, 0, 0, 9, 0, 0, 0, 7};
            n = rtcp ? 8 : 12;
            assert(srtp_runtime_packet(tx, 1, rtcp, bytes, sizeof(bytes), &n) == 0);
            assert(srtp_runtime_packet(rx, 0, rtcp, bytes, sizeof(bytes), &n) == 0);
            assert(tx->dtls_used[rtcp] == maximum && rx->dtls_used[rtcp] == maximum);
            /* A new SSRC cannot reset the actual key's usage. */
            bytes[rtcp ? 7 : 11] = 10;
            uint8_t before[128]; memcpy(before, bytes, sizeof(bytes));
            for (int i = 0; i < 3; i++) {
                assert(srtp_runtime_packet(tx, 1, rtcp, bytes, sizeof(bytes), &n) == srtp_err_status_key_expired);
                assert(srtp_runtime_packet(rx, 0, rtcp, bytes, sizeof(bytes), &n) == srtp_err_status_key_expired);
                assert(!memcmp(before, bytes, sizeof(bytes)));
            }
        }
        srtp_runtime_free(tx); srtp_runtime_free(rx);
        o.direction = 3; tx = NULL;
        assert(srtp_runtime_create_dtls(&o, &tx) == srtp_err_status_bad_param && !tx);
    }
    assert(srtp_shutdown() == 0);
    puts("PASS DTLS profile limits: both directions, RTP/SRTCP isolation, all SSRCs, terminal exhaustion and no state export");
}
