# Private SRTP state engine

The Runtime uses `srtp_runtime.h`, an exclusive opaque owner of one actual master
key plus salt, profile, direction and declared header-encryption/replay policy. A bidirectional owner
keeps both directions in one key lease and rejects an SSRC changing direction.
Only AES_CM_128_HMAC_SHA1_80 and AEAD_AES_128/256_GCM with full 16-byte GCM tags
are admitted. No MKI, automatic key changes, ROC resets or repeated transmission.

State version 1 is an explicit big-endian schema, not a C structure dump. It
contains the profile, direction, replay-window size, sorted encrypted-extension
IDs, SHA-256 key-material binding, shared key-use limit/state, and every SSRC's
RTP index, pending ROC, RTP replay bitmap, SRTCP index and SRTCP replay bitmap.
Restore constructs a fresh candidate and publishes it only after all validation.
Cipher and authentication working buffers are reconstructed from the supplied
key; per-packet IVs are initialized by the library. Dynamically added streams
share the original key-use limit. The restricted API never exposes a pending
ROC mutation, so imported nonzero pending ROC is rejected.

The caller must encrypt and authenticate state, prevent rollback and concurrent
leases of the actual key, reject missing state for key reuse, and durably save
advanced state before sending ciphertext or delivering verified plaintext.
This API does not persist state, expose keys, reconnect, or restore an Execution.
Errors can advance native state; no failed packet may be emitted or delivered.

Two native terminal-boundary fixes accompany this API: repeated use after key
exhaustion cannot wrap the remaining-use counter, and packet-index estimation
cannot roll the final ROC back to zero. The normal libSRTP wire engine remains
responsible for all packet parsing, cryptography, authentication and replay.

`tests/state.c` covers all three profiles, sequence rollover, multiple SSRCs,
RTP/SRTCP duplicate and stale rejection after restore, future wire equivalence,
malformed/mismatched state, key exhaustion and final-ROC exhaustion. CMake adds
it to the existing test suite when `LIBSRTP_TEST_APPS` and `ENABLE_OPENSSL` are on.
`tests/interop.py` compiles a separate unmodified-libSRTP peer and exchanges 400
RTP/SRTCP packets in each direction/profile, restoring the Runtime context after
every packet. These are native-library checks, not Runtime persistence acceptance.

`build_native.py` builds from a clean committed checkout with an explicit
OpenSSL prefix and records the source commit and artifact digests. Platform
packaging must bundle and relocate the resulting dependency closure.
