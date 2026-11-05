/*
 * gori_core.h: C interface of the Krypton Ø cryptographic core (Rust).
 *
 * This header is written by hand. The header_matches_exports test (`cargo test`) checks it against the
 * functions exported by src/ffi.rs, so when you add a function, update both.
 *
 * Conventions
 *  - Return value 0 = success, anything else is an error code. gori_error_message(code) gives a human-readable message
 *  - A GoriBuf is a result allocated by Rust. Always release it with gori_buf_free (it is zeroed before being freed)
 *  - The caller supplies fixed-size buffers: public key 32, signature 64, handle 33 (32 hex chars + NUL) bytes
 *  - Only gori_slot_secret exports a private key. It exists for platform secure storage (iOS Keychain, Android Keystore), and the key is never passed to JavaScript
 *  - Store a key in the vault under the name from gori_slot_vault_name and load it with gori_load_vault under the same name: the name identifies the format.
 *    Since the post-quantum version, the 32 bytes for ACCOUNT and ENC are seeds. The legacy names ("account", "enc") give GORI_ERR_STALE_KEY
 *  - A single GoriCore may be called from several threads (it locks internally)
 *  - Output pointers are checked before any state changes (if one is NULL, nothing changes and GORI_ERR_INVALID_ARGUMENT is returned)
 */
#ifndef GORI_CORE_H
#define GORI_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GoriCore GoriCore;

typedef struct GoriBuf {
  uint8_t *ptr;
  size_t len;
} GoriBuf;

/* Private key slots */
enum {
  GORI_SLOT_ACCOUNT = 0,  /* identity seed → Ed25519 identity key + ML-DSA-65 (vault name "account-seed-v2") */
  GORI_SLOT_DEVICE = 1,   /* Ed25519 device key (vault name "device") */
  GORI_SLOT_ENC = 2,      /* encryption seed → X25519 + ML-KEM-768 (vault name "enc-seed-v2") */
  GORI_SLOT_RECOVERY = 3, /* X25519 ephemeral receiving key for legacy guardian recovery (vault name "recovery") */
};

#define GORI_HANDLE_BUF_LEN 33

/* Post-quantum byte layouts */
#define GORI_HEK_LEN 1216                 /* hybrid public key = pk_M(1184, ML-KEM-768) ‖ pk_X(32, X25519) */
#define GORI_OUTER_ENVELOPE_LEN 1201      /* 0x02 ‖ ct(1120) ‖ nonce(24) ‖ AEAD(kid 8 ‖ key 32) */
#define GORI_INNER_ENVELOPE_LEN 104       /* ephPub(32) ‖ nonce(24) ‖ AEAD(key 32), used only inside pair notes */
#define GORI_PQ_SIG_PK_LEN 1952           /* ML-DSA-65 public key pk_D */
#define GORI_PQ_SIG_LEN 3309              /* ML-DSA-65 signature dq */

/* Outer envelope purposes (HKDF context) */
enum {
  GORI_OUTER_ENVELOPE = 0, /* "gori-pq/envelope-v2": key envelope placed on the outer layer */
  GORI_OUTER_NOTE = 1,     /* "gori-pq/note-v2":     body sealing for request notes, profile-card keys, invite bundles, etc. */
  GORI_OUTER_KEEP = 2,     /* "gori-pq/keep-v2":     sealed inbox copies and pair bundles */
};

/* Notification hint key ring (gori_open_hint): kinds and layout. Matches the app's JavaScript implementation */
enum {
  GORI_HINT_PAIR = 1, /* "gori/hint-v1|pair": pair mailbox hint (pair secret) */
  GORI_HINT_TALK = 2, /* "gori/hint-v1|talk": talk mailbox hint (conversation secret) */
  GORI_HINT_CALL = 3, /* "gori/hint-v1|call": call wake-up hint (pair secret) */
};
#define GORI_HINT_RECORD_LEN 49   /* kind 1 ‖ peer 16 ‖ key 32 */
#define GORI_HINT_RING_MAX 1024   /* maximum number of records in a ring */
#define GORI_HINT_TAG_LEN 17      /* kind ‖ peer of the record that opened */

/* Error codes (partial). The full list is in src/error.rs */
enum {
  GORI_OK = 0,
  GORI_ERR_NO_ACCOUNT_KEY = 1,
  GORI_ERR_NO_DEVICE_KEY = 2,
  GORI_ERR_NO_ENCRYPTION_KEY = 3,
  GORI_ERR_UNKNOWN_HANDLE = 4,
  GORI_ERR_BAD_CIPHERTEXT = 5,
  GORI_ERR_DECRYPT_FAILED = 6,
  GORI_ERR_BAD_ENVELOPE = 7,
  GORI_ERR_NOT_FOR_ME = 8,
  GORI_ERR_RECOVERY_NOT_STARTED = 15,
  GORI_ERR_BAD_BACKUP = 16,
  GORI_ERR_INVALID_ARGUMENT = 18,
  GORI_ERR_KEY_CONFLICT = 22,
  GORI_ERR_BAD_SHARE_COUNT = 26,
  GORI_ERR_WEAK_KEY = 27,
  GORI_ERR_DUPLICATE_GUARDIAN = 28,
  GORI_ERR_RESERVED_STATEMENT = 29, /* gori_sign refuses to sign messages that start with "gori-core/" */
  GORI_ERR_ACCOUNT_MISMATCH = 30,
  GORI_ERR_TICKET_INPUT = 31, /* invite ticket: kind, index count (1 to 64), duplicate indices, element count */
  GORI_ERR_TICKET_POINT = 32, /* invite ticket: an element or public key is non-canonically encoded or is the identity */
  GORI_ERR_TICKET_PROOF = 33, /* invite ticket: the issuance proof (DLEQ) does not verify; nothing is output */
  GORI_ERR_BAD_PHRASE = 34,   /* recovery phrase: not 18 words, a word not in the list, or a bad checksum */
  GORI_ERR_STALE_KEY = 35,    /* legacy-format vault name or recovery backup (version 3); never silently read as a seed. The account must be re-created */
  GORI_ERR_NEED_HYBRID_KEY = 36, /* outer-layer sealing was given a key that is not an HEK (1216) */
  GORI_ERR_INTERNAL = 99,
};

/* ── Lifetime ── */
GoriCore *gori_core_new(void);
void gori_core_free(GoriCore *core);
void gori_buf_free(GoriBuf buf);
const char *gori_error_message(int32_t code);

/* ── Private key slots (wrapper only) ── */
int32_t gori_generate(const GoriCore *core, uint32_t slot, uint8_t *out_pub32);
/* Vault entry name (static string, do not free). NULL for an unknown slot */
const char *gori_slot_vault_name(uint32_t slot);
/* Loads by vault entry name. Legacy names ("account", "enc") give GORI_ERR_STALE_KEY, unknown names GORI_ERR_INVALID_ARGUMENT */
int32_t gori_load_vault(const GoriCore *core, const char *vault_name, const uint8_t *secret,
                        size_t len, uint8_t *out_pub32 /* may be NULL */);
int32_t gori_slot_secret(const GoriCore *core, uint32_t slot, uint8_t *out_secret32);
int32_t gori_clear(const GoriCore *core, uint32_t slot);
int32_t gori_has(const GoriCore *core, uint32_t slot, uint8_t *out_has);
int32_t gori_public_key(const GoriCore *core, uint32_t slot, uint8_t *out_pub32);

/* ── Signing ── */
/* Signs any message, except core-only statements starting with "gori-core/", which are rejected (GORI_ERR_RESERVED_STATEMENT) */
int32_t gori_sign(const GoriCore *core, uint32_t slot, const uint8_t *msg, size_t len,
                  uint8_t *out_sig64);
/* Device certificate v2: sign(account, "gori-core/device-cert-v2\0" ‖ this core's device_pub) */
int32_t gori_sign_device_certificate(const GoriCore *core, uint8_t *out_sig64);
/* Encryption key signature v2: sign(account, "gori-core/enc-key-v2\0" ‖ this core's enc_pub) */
int32_t gori_sign_encryption_key(const GoriCore *core, uint8_t *out_sig64);
/* Encryption key signature v3 (es3): sign(account, "gori-core/enc-key-v3\0" ‖ pk_X(32) ‖ pk_M(1184)), over this core's HEK */
int32_t gori_sign_encryption_key_v3(const GoriCore *core, uint8_t *out_sig64);
/* 1 = valid signature, 0 = not. Strict verification: small-order, non-canonical or torsion-containing public keys, small-order R and non-canonical S all give 0 */
int32_t gori_verify(const uint8_t *pubkey, size_t pub_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len);

/* ── Post-quantum public key and identity key binding ── */
/* This core's HEK = pk_M ‖ pk_X. pk_X is the same as gori_public_key(GORI_SLOT_ENC) */
int32_t gori_encryption_hybrid_key(const GoriCore *core, uint8_t *out_hek1216);
/* Checks a received HEK (no core needed). 0 = usable, GORI_ERR_NEED_HYBRID_KEY = wrong length, GORI_ERR_WEAK_KEY = failed the strict pk_X check or the pk_M modulus check */
int32_t gori_check_hybrid_key(const uint8_t *hek, size_t len);
/* Notification hint key ring (src/hint.rs), no core needed. ring = 0x01 ‖ (kind 1 ‖ peer 16 ‖ key 32)* (up to 1,024 records),
 * kinds = bitmask of kinds to try (1 << kind), sealed = base64-decoded g (nonce 24 ‖ XChaCha20-Poly1305, AD "gori/hint-v1|<kind>").
 * On success out = plaintext (gori_buf_free) and out_tag17 = kind ‖ peer of the record that opened it. If no key opens it, GORI_ERR_DECRYPT_FAILED; a malformed ring gives GORI_ERR_INVALID_ARGUMENT */
int32_t gori_open_hint(const uint8_t *ring, size_t ring_len, uint32_t kinds, const uint8_t *sealed, size_t sealed_len,
                       GoriBuf *out, uint8_t *out_tag17);
/* Identity key binding (public values): pk_D = ML-DSA-65 public key, dh = SHA3-256("gori-core/pq-sig-id-v1\0" ‖ pk_D),
 * ds = Ed25519(ik, "gori-core/pq-sig-bind-v1\0" ‖ ik ‖ dh), dq = ML-DSA-65(same statement, ctx "gori-core") */
int32_t gori_pq_sig_binding(const GoriCore *core, uint8_t *out_pk_d1952, uint8_t *out_dh32,
                            uint8_t *out_ds64, uint8_t *out_dq3309);
/* 1 = the binding is valid, 0 = not (also 0 for wrong lengths) */
int32_t gori_verify_pq_sig_binding(const uint8_t *ik, size_t ik_len, const uint8_t *pk_d,
                                   size_t pk_d_len, const uint8_t *dh, size_t dh_len,
                                   const uint8_t *ds, size_t ds_len, const uint8_t *dq,
                                   size_t dq_len);

/* ── Content keys ── */
int32_t gori_create_content_key(const GoriCore *core, char *out_handle33);
int32_t gori_encrypt(const GoriCore *core, const char *handle, const uint8_t *pt, size_t len,
                     GoriBuf *out);
int32_t gori_decrypt(const GoriCore *core, const char *handle, const uint8_t *ct, size_t len,
                     GoriBuf *out);
/* Outer envelope v2 (hybrid, GORI_OUTER_ENVELOPE_LEN). purpose = GORI_OUTER_*. The recipient key must be an HEK (1216):
 * otherwise GORI_ERR_NEED_HYBRID_KEY, and GORI_ERR_WEAK_KEY if it fails the key check */
int32_t gori_seal_outer(const GoriCore *core, const char *handle, uint32_t purpose,
                        const uint8_t *hek, size_t len, GoriBuf *out);
/* Exactly 1201 bytes only (otherwise GORI_ERR_BAD_ENVELOPE). Opens only with the same purpose used for sealing */
int32_t gori_open_outer(const GoriCore *core, uint32_t purpose, const uint8_t *envelope, size_t len,
                        char *out_handle33);
/* Inner envelope (X25519, GORI_INNER_ENVELOPE_LEN; same bytes as the earlier gori_seal_to). The recipient key is pk_X (32).
 * Used only inside notes sealed with a pair secret */
int32_t gori_seal_inner(const GoriCore *core, const char *handle, const uint8_t *recipient,
                        size_t len, GoriBuf *out);
/* Exactly 104 bytes only (otherwise GORI_ERR_BAD_ENVELOPE) */
int32_t gori_open_inner(const GoriCore *core, const uint8_t *envelope, size_t len,
                        char *out_handle33);
int32_t gori_wrap_key(const GoriCore *core, const char *kek, const char *key, GoriBuf *out);
int32_t gori_unwrap_key(const GoriCore *core, const char *kek, const uint8_t *wrapped,
                        size_t len, char *out_handle33);

/* ── Chunked files (paths are file system paths, not file:// URLs) ── */
int32_t gori_encrypt_file(const GoriCore *core, const char *handle, const char *in_path,
                          const char *out_path);
int32_t gori_decrypt_file(const GoriCore *core, const char *handle, const char *in_path,
                          const char *out_path);
/* Decrypts to a cache file that can be downloaded again, without fsync. If out_path + ".part" exists, it is truncated and written to */
int32_t gori_decrypt_cache_file(const GoriCore *core, const char *handle, const char *in_path,
                                const char *out_path);
/* Decrypt while downloading: plaintext [start, start+len) of a chunked file still being downloaded (its current size is the received prefix, total is the full ciphertext length).
   Returns 37 (StreamNotYet) if that range has not arrived yet. Release out with gori_buf_free (it is zeroed) */
int32_t gori_decrypt_file_range(const GoriCore *core, const char *handle, const char *in_path,
                                uint64_t total, uint64_t start, uint64_t len, GoriBuf *out);

/* ── Account recovery ── */
/* 2 to 16 guardians, all distinct (different encodings of the same key count as the same guardian), none equal to our own encryption key */
int32_t gori_prepare_recovery(const GoriCore *core, const uint8_t *pubkeys /* 32*count */,
                              size_t count, size_t threshold, GoriBuf *out_backup,
                              uint8_t *out_server_share32, GoriBuf *out_shares,
                              size_t *out_share_len);
int32_t gori_begin_recovery(const GoriCore *core, uint8_t *out_pub32, uint8_t *out_created);
int32_t gori_reseal_share(const GoriCore *core, const uint8_t *sealed, size_t sealed_len,
                          const uint8_t *to_pub, size_t to_len, GoriBuf *out);
/* 1 to 16 shares (105 bytes each), server share 32 bytes. If the restored account public key differs from
 * expected_account_pub (32), GORI_ERR_ACCOUNT_MISMATCH; if it would overwrite a different key already loaded,
 * GORI_ERR_KEY_CONFLICT. Neither changes the core's slots. The wrapper writes to the Keychain only after a 0 return */
int32_t gori_complete_recovery(const GoriCore *core, const uint8_t *backup, size_t backup_len,
                               const uint8_t *const *shares, const size_t *share_lens,
                               size_t count, const uint8_t *server_share,
                               size_t server_share_len, const uint8_t *expected_account_pub,
                               size_t expected_len, uint8_t *out_account_pub32,
                               uint8_t *out_enc_pub32);

/* ── Recovery v3: paper phrase ──
 * Phrase = 18 BIP39 English words (192-bit R + 6-bit checksum, no PBKDF2 seed derivation). UTF-8 bytes, words separated by ASCII whitespace.
 * S = HKDF(R ‖ U, "gori-self-recovery-v3"), locator L = HKDF(R, "gori-recovery-locator").
 * The backup is 105 bytes, first byte (version) = 4 (both 32-byte values are seeds, post-quantum version; the version byte is AEAD aad). Version 3 (before
 * the post-quantum upgrade) gives GORI_ERR_STALE_KEY. The phrase is shown once on screen. The phrase alone cannot open the backup: S also needs U */
#define GORI_BACKUP_V4 4
/* Requires the account and encryption keys. out_phrase = 18 lowercase words joined by single spaces (no NUL) */
int32_t gori_prepare_self_recovery(const GoriCore *core, GoriBuf *out_phrase, GoriBuf *out_backup,
                                   uint8_t *out_server_share32, uint8_t *out_locator32);
/* No core needed (new device). An invalid phrase gives GORI_ERR_BAD_PHRASE */
int32_t gori_recovery_locator(const uint8_t *phrase, size_t phrase_len, uint8_t *out_locator32);
/* scrypt (RFC 7914), no core needed (stateless). Computes the app's PIN hash (N = 2^14, r 8, p 1, 32 bytes) in place of JavaScript;
 * output is byte-identical to @noble/hashes (tests/scrypt.rs). log_n 10 to 20, r 1 to 16, p 1 to 4, out_len 16 to 64: outside these ranges
 * GORI_ERR_INVALID_ARGUMENT and nothing is written to out. pw is borrowed read-only and stays owned by the caller */
int32_t gori_scrypt(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len, uint32_t log_n,
                    uint32_t r, uint32_t p, uint8_t *out, size_t out_len);
/* Version 3 gives GORI_ERR_STALE_KEY, anything other than 4 gives GORI_ERR_BAD_BACKUP. A mismatch with the expected public key gives GORI_ERR_ACCOUNT_MISMATCH,
 * overwriting a different key gives GORI_ERR_KEY_CONFLICT; neither changes the core's slots. The recovery ephemeral key slot (GORI_SLOT_RECOVERY) is not touched */
int32_t gori_complete_self_recovery(const GoriCore *core, const uint8_t *phrase, size_t phrase_len,
                                    const uint8_t *backup, size_t backup_len,
                                    const uint8_t *server_share, size_t server_share_len,
                                    const uint8_t *expected_account_pub, size_t expected_len,
                                    uint8_t *out_account_pub32, uint8_t *out_enc_pub32);

/* ── Invite tickets (RFC 9497 VOPRF ristretto255-SHA512) ──
 * For each (kind, period, index), the input and blind are derived deterministically from the account key seed and the period salt (32B), so the core keeps no state.
 * The wrapper creates one period salt per period, keeps it in the vault (iOS Keychain, Android Vault) and deletes it when the period ends (it is never passed to JavaScript).
 * Blinds and seeds never cross the boundary. Only blinded elements and tickets (input 32 ‖ output 64) leave */
#define GORI_TICKET_KIND_INVITE 1
#define GORI_TICKET_KIND_BOX 2
#define GORI_TICKET_BATCH_MAX 64
/* out_blinded is 32*count. Does not change state. Without an account key GORI_ERR_NO_ACCOUNT_KEY,
 * an all-zero salt gives GORI_ERR_TICKET_INPUT */
int32_t gori_ticket_blind(const GoriCore *core, uint8_t kind, uint32_t period,
                          const uint8_t *period_salt32, const uint32_t *indices, size_t count,
                          uint8_t *out_blinded);
/* evaluated 32*count, proof 64. out_inputs 32*count, out_outputs 64*count.
 * On failure (including a bad proof) nothing is written to the outputs */
int32_t gori_ticket_finalize(const GoriCore *core, uint8_t kind, uint32_t period,
                             const uint8_t *period_salt32, const uint32_t *indices, size_t count,
                             const uint8_t *server_pub32, const uint8_t *evaluated,
                             const uint8_t *proof64, uint8_t *out_inputs, uint8_t *out_outputs);

/* Erases all private keys and content keys (bot key sets too) */
int32_t gori_forget_all(const GoriCore *core);

/* ── Bot keys (src/bot.rs) ──
 * Creates a new bot key set (identity, device and encryption seeds). out_handle 33, out = 6893-byte public bundle (public values only, gori_buf_free) */
int32_t gori_bot_create(const GoriCore *core, char *out_handle33, GoriBuf *out);
/* Writes the key file to path: one line, meta (UTF-8 JSON object without seeds, up to 8192 bytes) plus a "seeds" field */
int32_t gori_bot_key_file(const GoriCore *core, const char *handle, const uint8_t *meta, size_t len, const char *path);
/* Erases a bot key set (does nothing if it does not exist) */
int32_t gori_bot_forget(const GoriCore *core, const char *handle);
/* Owner's bot signatures: op 0 bot certificate (no salt, payload 80 → signature 64), 1 admin key public key (salt 16 → 32),
 * 2 delete bot (salt 16, payload 24 → public key 32 ‖ signature 64), 3 key rotation (salt 16, payload 56 → public key 32 ‖ signature 64). Release out with gori_buf_free */
int32_t gori_bot_sign(const GoriCore *core, uint32_t op, const uint8_t *salt, size_t salt_len, const uint8_t *payload,
                      size_t payload_len, GoriBuf *out);

#ifdef __cplusplus
}
#endif

#endif /* GORI_CORE_H */
