/* Versioned, portable cryptographic state. BSD-3-Clause, like libSRTP. */
#ifndef SRTP_RUNTIME_H
#define SRTP_RUNTIME_H
#include "srtp.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct srtp_runtime_context srtp_runtime_context;
/* Call srtp_init() once before use. All operations on a context are exclusive.
 * Profiles: 1 AES_CM_128_HMAC_SHA1_80, 2 AEAD_AES_128_GCM, 3 AEAD_AES_256_GCM.
 * Direction: 1 sender, 2 receiver, 3 both with distinct SSRCs. Key includes the
 * profile's master salt. Window is an explicit multiple of 32, 64..32736.
 * Encrypted extension IDs must be strictly increasing, 1..255. No MKI or
 * repeated transmission. No pointer in these options is retained after
 * construction. */
typedef struct {
    uint32_t profile;
    uint32_t direction;
    const uint8_t *key;
    size_t key_length;
    uint32_t replay_window;
    const uint32_t *encrypted_extensions;
    size_t encrypted_extension_count;
} srtp_runtime_options;

srtp_err_status_t srtp_runtime_create(const srtp_runtime_options *options,
                                      srtp_runtime_context **out);
/* Fresh DTLS exporter context, never exportable/restorable. Enforces the
 * profile-specific per-key RTP and SRTCP usage limits across all SSRCs.
 * A DTLS write key has exactly one direction; Both is rejected. */
srtp_err_status_t srtp_runtime_create_dtls(const srtp_runtime_options *options,
                                           srtp_runtime_context **out);
/* Import constructs a new context atomically. Keys and every policy field
 * must match. Blob is not authenticated: caller MUST authenticate/encrypt it,
 * prevent rollback/reset/concurrent key leases and fail closed if absent. */
srtp_err_status_t srtp_runtime_restore(const srtp_runtime_options *options,
                                       const uint8_t *blob, size_t length,
                                       srtp_runtime_context **out);
/* NULL output queries required length; too-small output is untouched. Numeric
 * fields and replay words are big endian; no native structure serialization.
 * Includes all SSRCs, RTP index/ROC/replay, SRTCP index/replay and key use. */
srtp_err_status_t srtp_runtime_export(srtp_runtime_context *context,
                                      uint8_t *output, size_t *length);
void srtp_runtime_free(srtp_runtime_context *context);
/* sending and rtcp are 0 or 1. sending selects protect/unprotect. The native
 * library performs packet parsing, authentication, replay checks and index
 * updates. Caller MUST save updated state before wire send or plaintext
 * delivery. After an error, no packet bytes may be exposed. State may have
 * advanced. */
srtp_err_status_t srtp_runtime_packet(srtp_runtime_context *context,
                                      int sending, int rtcp, uint8_t *packet,
                                      size_t capacity, size_t *length);
#ifdef __cplusplus
}
#endif
#endif
