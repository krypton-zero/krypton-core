# Krypton Ø crypto core

`gori-core` is the Rust library that does the cryptography on the device in Krypton Ø, an invite-only
social app for iOS and Android. Posts, replies, profiles, photos and videos are encrypted on the phone
before anything is uploaded. The account, device and encryption keys, and the content keys the core
creates, are generated and used inside this crate.

We publish it so that anyone can check one specific claim:

> Everything the server stores or relays about users' content (posts, messages, profiles, photos and
> videos, and the keys that open them) is encrypted on the device before upload. Someone who obtains
> everything the server holds still cannot decrypt users' content, because that needs key material that
> exists only on users' devices.

This repository is the on-device crypto core only. It does not contain the app's user interface, the
native Swift and Kotlin wrappers, or any server code.

**Status:** pre-1.0. The wire formats are in use by the shipping app and are covered by test vectors. The
Rust API may still change. No independent audit report has been published yet; review is welcome (see
[SECURITY.md](SECURITY.md)).

## Contents

- [Where it sits](#where-it-sits)
- [What the core is designed to guarantee](#what-the-core-is-designed-to-guarantee)
- [Primitives](#primitives)
- [Keys held by a core instance](#keys-held-by-a-core-instance)
- [Formats](#formats)
- [Signed statements and verification rules](#signed-statements-and-verification-rules)
- [Account recovery](#account-recovery)
- [Other modules](#other-modules)
- [Memory hygiene](#memory-hygiene)
- [C ABI and JNI](#c-abi-and-jni)
- [Building and testing](#building-and-testing)
- [Test vectors](#test-vectors)
- [License](#license)

## Where it sits

```
App UI (React Native / JavaScript)    sees public keys, ciphertexts, envelopes, opaque handles
        |
Native wrapper                        iOS: Swift + Keychain    Android: Kotlin + Android Keystore
        |                             (stores private keys; never passes them to JavaScript)
C ABI (include/gori_core.h)  /  JNI (src/jni.rs, Android only)
        |
gori-core (this crate)                key generation, signing, sealing, recovery, file encryption
```

Operations with the account, device and encryption keys, and with the content keys the core creates,
happen inside the crate. The JavaScript layer refers to those content keys through opaque handles (16
random bytes, hex encoded). A handle is not key material and decrypts nothing by itself.

## What the core is designed to guarantee

- **Content is encrypted before it leaves the device.** Content keys are random 256-bit keys created inside
  the core, and every encryption uses XChaCha20-Poly1305 with a fresh 192-bit random nonce.
- **Content keys leave the core only in sealed form.** A content key is either sealed to a recipient's
  public key or wrapped under another content key (the 72-byte wrapped key below). A key envelope that
  passes through or rests on the server, a mailbox or a push provider is the hybrid outer envelope (X25519
  combined with ML-KEM-768, following X-Wing); opening it needs the recipient's encryption seed, which
  exists only on the recipient's devices. The X25519-only inner envelope is used only inside a note that is
  already sealed with a pair secret.
- **Private keys and content keys never reach the JavaScript layer.** The only export of a slot's private
  key is to the native wrapper, which stores the seeds in the platform's secure storage. Bot key sets are
  written straight to a key file for their owner (see [Other modules](#other-modules)). The one secret
  deliberately shown to the user is the paper recovery phrase, displayed once so it can be written down.
- **Keys are bound to an identity.** An account identity combines Ed25519 and ML-DSA-65, and both keys
  sign one statement that binds them together. The encryption key signature covers both the X25519 and
  the ML-KEM public key, so a substituted post-quantum key does not verify against the account key.
- **Core statements cannot be repurposed.** Every core statement (the `gori-core/...` statements under
  [Signed statements](#signed-statements-and-verification-rules)) carries a purpose-specific prefix, and the
  general signing call refuses that namespace, so bytes chosen outside the core can never produce a core
  statement.
- **Recovery does not hand the server the keys.** Both recovery paths need a server-held share `U` *and* a
  secret the server never sees (guardian shares, or the paper phrase).

## Primitives

| Primitive | Specification | Implementation | Used for |
|---|---|---|---|
| Ed25519 | RFC 8032 | `ed25519-dalek` 2 (`verify_strict`), `curve25519-dalek` 4 for key checks | account identity, device keys, signed statements |
| ML-DSA-65 | FIPS 204 | `ml-dsa` 0.1.1 (pure ML-DSA, hedged, context `gori-core`) | post-quantum half of the account identity |
| X25519 | RFC 7748 | `x25519-dalek` 2 | classical half of the encryption key, inner envelopes, recovery shares |
| ML-KEM-768 | FIPS 203 | `ml-kem` 0.3.3 | post-quantum half of the encryption key |
| X-Wing | draft-connolly-cfrg-xwing-kem-06 | in crate (`src/pq.rs`), cross-checked against the `x-wing` crate | hybrid KEM for outer envelopes |
| XChaCha20-Poly1305 | RFC 8439 + draft-irtf-cfrg-xchacha | `chacha20poly1305` 0.10 | content, key wrapping, envelope bodies, backups, stream chunks |
| HKDF-SHA256 | RFC 5869 | `hkdf` 0.12, `sha2` 0.10 | envelope keys, recovery secrets, ticket and bot derivations |
| SHA3-256, SHAKE256 | FIPS 202 | `sha3` 0.12, `shake` 0.1 | X-Wing combiner, seed expansion, identity binding |
| VOPRF ristretto255-SHA512 | RFC 9497 | `voprf` 0.5.0 | anonymous tickets |
| Shamir secret sharing | GF(2^8), polynomial 0x11b | in crate (`src/shamir.rs`), constant-time arithmetic | guardian recovery |
| scrypt | RFC 7914 | `scrypt` 0.11 (N=2^14, r=8, p=1, 32 bytes) | PIN hashing |
| BIP39 English word list | BIP39 | in crate (`src/bip39_en.rs`) | 18-word paper recovery phrase (no PBKDF2 step) |

Randomness comes from the operating system CSPRNG (`OsRng`). Tests inject a seeded generator so the vectors
are reproducible.

## Keys held by a core instance

| Slot | Content | Derived keys |
|---|---|---|
| `Account` | 32-byte identity seed `isd` | `SHAKE256("gori-core/id-seed-v1\0" ‖ isd, 64)` = Ed25519 secret ‖ ML-DSA-65 seed ξ |
| `Device` | Ed25519 seed (one per device) | Ed25519 key pair |
| `Enc` | 32-byte encryption seed | `SHAKE256(seed, 96)` = ML-KEM-768 seed d‖z ‖ X25519 secret (X-Wing key generation) |
| `Recovery` | X25519 secret | temporary receiving key on a new device during guardian recovery |

ML-KEM and ML-DSA keys are never stored; they are re-derived from the seed on each use. The derivation only
runs from the seed outwards, never from the X25519 secret to the ML-KEM seed.

Besides the slots, a core holds a table of content keys (handle to 32-byte key) and, briefly, bot key sets
(see [Other modules](#other-modules)).

The wrapper stores slot secrets under names returned by `gori_slot_vault_name` (`account-seed-v2`, `device`,
`enc-seed-v2`, `recovery`). The name doubles as a format tag; values stored under the older names `account`
and `enc` are rejected with `StaleKey`.

## Formats

All lengths are in bytes. `‖` is concatenation. AEAD is XChaCha20-Poly1305 with a 16-byte tag.

**Content ciphertext**: `nonce(24) ‖ AEAD(content_key, plaintext, aad = "")`

**Wrapped key** (72): `nonce(24) ‖ AEAD(kek, key(32), aad = "gori-key-wrap-v1")`

**Hybrid public key HEK** (1216): `pk_M(1184) ‖ pk_X(32)`

**Outer envelope v2** (1201 for a 32-byte key):

```
0x02 ‖ ct(1120) ‖ nonce(24) ‖ AEAD(wrap_key, kid(8) ‖ payload, aad = 0x02 ‖ ct)
ct       = ct_M(1088) ‖ ct_X(32)                  (fresh ephemeral X25519 key per seal)
ss       = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")
wrap_key = HKDF-SHA256(ss, salt = none, info = context ‖ 0x00 ‖ 0x02)
kid      = SHA-256("gori-pq/kid-v1\0" ‖ HEK)[0..8]
context  = "gori-pq/envelope-v2" | "gori-pq/note-v2" | "gori-pq/keep-v2"
```

The cleartext part names no recipient. The key identifier is inside the AEAD. An envelope sealed for one
context does not open under another, and openers check the exact length, so an outer envelope cannot be
replaced by an inner one.

**Inner envelope** (104), used only inside a note that is already sealed with a pair secret:

```
eph_pub(32) ‖ nonce(24) ‖ AEAD(wrap_key, key(32), aad = "")
wrap_key = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub ‖ recipient_pub, info = "circle-envelope-v1")
```

Recipient X25519 keys must be canonical, on the curve (not the twist) and not of small order; all-zero
shared secrets are rejected. Recipient HEKs go through the same X25519 check plus the FIPS 203 encapsulation
key check.

**Stream format GORS v1** (large files such as video):

```
header(32) = "GORS" ‖ 0x01 ‖ chunk size exponent e ‖ 0x0000 ‖ base nonce N(24)
chunk i    = AEAD(key, N xor (0^16 ‖ u64_be(i)), aad = header ‖ (last ? 0x01 : 0x00), plaintext_i)
```

The chunk index in the nonce detects reordering, the last-chunk flag detects truncation and extension, and
the header in the AAD prevents mixing chunks between files. Range decryption opens only the chunks needed.

## Signed statements and verification rules

| Statement | Message signed with the account key |
|---|---|
| Device certificate v2 | `"gori-core/device-cert-v2\0" ‖ device_pub(32)` |
| Encryption key signature v2 | `"gori-core/enc-key-v2\0" ‖ enc_pub(32)` |
| Encryption key signature v3 | `"gori-core/enc-key-v3\0" ‖ pk_X(32) ‖ pk_M(1184)` |
| Identity binding | `dh = SHA3-256("gori-core/pq-sig-id-v1\0" ‖ pk_D)`; Ed25519 and ML-DSA-65 both sign `"gori-core/pq-sig-bind-v1\0" ‖ ik ‖ dh` |

`Core::sign` refuses any message that starts with `gori-core/` (`ReservedStatement`). These statements are
produced only by the dedicated functions, and only for the core's own keys.

Ed25519 verification in this crate is strict, and other verifiers of these statements need the same rules
to reach the same verdicts:

- the public key is the canonical encoding of a point that is not of small order and is torsion-free;
- the signature passes `verify_strict` (canonical `S`, `R` not of small order).

`tests/vectors/strict.json` lists accept and reject cases for these rules.

## Account recovery

There are two recovery paths. Both encrypt the account seed and encryption seed (64 bytes) into a backup and
split the decryption secret so that the server's part alone is not enough.

**Paper phrase (version byte 4).** The core draws a 192-bit secret `R` and a 32-byte server share `U`.

```
S       = HKDF-SHA256(R ‖ U, info = "gori-self-recovery-v3")
L       = HKDF-SHA256(R, info = "gori-recovery-locator")     (the server stores only SHA-256(L))
backup  = 0x04 ‖ nonce(24) ‖ AEAD(S, account_seed ‖ enc_seed, aad = 0x04)
phrase  = BIP39 encoding of R: 18 words (R ‖ first 6 bits of SHA-256(R))
```

Word lookup always scans the whole list, so its timing does not reveal a word's position. On completion the core checks the recovered account key
against the expected one before installing anything.

**Guardians (Shamir, version byte 1, the earlier path).** A 32-byte secret `T` is split into `n` shares (2 to 16 guardians, threshold at least 2)
and each share is sealed to a guardian's X25519 key (105-byte share envelopes, context
`gori-recovery-share-v1`). The backup is `0x01 ‖ nonce(24) ‖ AEAD(S, account_seed ‖ enc_seed)` with
`S = HKDF-SHA256(T ‖ U, info = "gori-recovery-secret-v1")`.
Duplicate guardians (including alternative encodings of the same key and torsion-shifted keys) and the
user's own encryption key are rejected before any secret is drawn. To recover, guardians re-seal their share
to a temporary key generated on the new device. `complete_recovery` checks share count and lengths first,
then checks that the recovered account matches the expected public key, and refuses to replace a different
key already on the device.

## Other modules

- **`ticket`, `oprf`**: anonymous tickets built on RFC 9497 VOPRF (ristretto255-SHA512). The client derives
  ticket inputs and blinds deterministically from the account seed and a per-period random salt, sends only
  blinded elements, and verifies the server's DLEQ proof against a pinned server public key before
  unblinding. The server sees the ticket only when it is redeemed and cannot link it to the issuance. The
  server-side operations are behind the `test-server` feature and are not part of the app library.
- **`hint`**: a key ring that lets the native notification handlers (iOS notification service extension,
  Android messaging service) open sealed notification previews while the app is not running. The ring contains only per-purpose keys derived with HKDF (`gori/hint-v1|pair`,
  `|talk`, `|call`), never the underlying pair or conversation secrets.
- **`bot`**: key sets for bot accounts created by a user. The seeds are written straight to a key file,
  are never put in secure storage or passed to JavaScript, and are dropped from the core afterwards. Bot certificates and admin signatures use their own
  `gori-core/bot-...` statements.
- **`phrase`, `bip39_en`**: recovery phrase encoding.
- **`stream`**: the GORS format above.

## Memory hygiene

Secret values are held in `zeroize::Zeroizing` buffers or types that wipe themselves on drop: slot secrets,
content keys (each boxed so table growth does not leave copies), expanded seeds, ML-KEM decapsulation keys,
ML-DSA signing keys, shared secrets, recovery shares, ticket seeds and blinds, and the recovery phrase.
Buffers returned across the C ABI are zeroed by `gori_buf_free`. File encryption reads and writes the file
handles directly without intermediate buffers.

`tests/zeroize.rs` installs an instrumented global allocator that scans every freed heap block for the
secrets a test is watching, and fails if any are found.

## C ABI and JNI

- `include/gori_core.h` declares the C ABI (49 functions), called by the iOS wrapper and, on Android, by
  `src/jni.rs`. Return value 0 means success; any other value is an error code, and
  `gori_error_message(code)` returns a static message.
- Variable-length results are returned in a `GoriBuf` that the caller frees with `gori_buf_free`.
- Every entry point that touches core state or caller memory runs inside `catch_unwind`, so no panic
  crosses the boundary; the two static string lookups (`gori_error_message`, `gori_slot_vault_name`) only
  return constant strings. Output pointers are validated before any state changes.
- `src/jni.rs` (compiled only for `target_os = "android"`) forwards to the same functions for the Kotlin
  wrapper and throws `GoriCoreException("<code>|<message>")` on failure.
- The crate is `#![deny(unsafe_code)]`; only `src/ffi.rs` and `src/jni.rs` opt out, for the boundary code.

## Building and testing

Requires a stable Rust toolchain (tested with Rust 1.98).

```sh
cargo test                     # unit, integration and vector tests (also enables the server-side VOPRF code)
cargo build --release --lib    # static library (libgori_core.a) and rlib
```

The app's build packages the library for iOS and Android; those packaging scripts are not part of this
repository. A quick timing benchmark for the post-quantum operations is available with
`cargo test --release --test pq -- --ignored --nocapture measure`.

## Test vectors

| File | Source |
|---|---|
| `rust.json`, `pq-rust.json`, `self-recovery-rust.json`, `oprf-rust.json`, `ticket.json`, `strict.json` | generated by this crate's tests with a seeded RNG; the tests fail if the files differ from what the code produces. Regenerate with `GORI_WRITE_VECTORS=1 cargo test` |
| `dev.json`, `self-recovery-dev.json`, `oprf-dev.json`, `hint-js.json` | produced by a separate JavaScript implementation (noble libraries) and checked here |
| `acvp-ml-kem-768.json`, `acvp-ml-dsa-65.json` | NIST ACVP vectors, extracted with `extract_acvp.py` |
| `rfc9497-ristretto255-voprf.json` | RFC 9497 Appendix A.1.2 vectors, extracted with `extract_rfc9497.py` |
| `xwing-draft06.json` | X-Wing draft 06 test vectors |

## License

Copyright (C) 2026 Fantagram, Inc.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License version 3 only (SPDX: `AGPL-3.0-only`) as published by the Free Software Foundation.
See [LICENSE](LICENSE).

## Contributions

This repository is published so that the cryptography can be reviewed. We do not accept pull requests.
To report a security problem, follow [SECURITY.md](SECURITY.md).
