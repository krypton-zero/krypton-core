//! Primitive operations. Each one corresponds one-to-one to a noble library call in the JavaScript reference implementation.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::pq;

pub type Secret32 = Zeroizing<[u8; 32]>;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

pub const ENVELOPE_INFO: &[u8] = b"circle-envelope-v1";
pub const SHARE_INFO: &[u8] = b"gori-recovery-share-v1";
pub const SECRET_INFO: &[u8] = b"gori-recovery-secret-v1";
pub const WRAP_AAD: &[u8] = b"gori-key-wrap-v1";
/// Self-recovery v3 (paper phrase): S = HKDF(R ‖ U, this label). The label differs from the guardian-share path (SECRET_INFO),
/// so neither path can open the other's backup
pub const SELF_RECOVERY_INFO: &[u8] = b"gori-self-recovery-v3";
/// Self-recovery v3 locator: L = HKDF(R, this label). The server stores only SHA-256(L). The label differs from the one used
/// for S, so S cannot be derived from L
pub const RECOVERY_LOCATOR_INFO: &[u8] = b"gori-recovery-locator";

// ── Statements only the core signs ──
//
// Each statement the core signs with the account key carries a purpose-specific prefix (domain separation). The general
// signing call ([`crate::core::Core::sign`]) refuses any message that starts with the prefix namespace (`gori-core/`), so
// bytes chosen outside the core (by the app's JavaScript layer) can never produce one of these statements.

/// Namespace of core-only statements. The general signing call rejects any message starting with these bytes (`Error::ReservedStatement`)
pub const CORE_STATEMENT_PREFIX: &[u8] = b"gori-core/";
/// Device certificate v2 = `sign(account, DEVICE_CERT_TAG ‖ device_pub(32))`, a 57-byte message
pub const DEVICE_CERT_TAG: &[u8] = b"gori-core/device-cert-v2\0";
/// Encryption key signature v2 = `sign(account, ENC_KEY_TAG ‖ enc_pub(32))`, a 53-byte message
pub const ENC_KEY_TAG: &[u8] = b"gori-core/enc-key-v2\0";
/// Encryption key signature v3 (`es3`) = `sign(account, ENC_KEY_V3_TAG ‖ pk_X(32) ‖ pk_M(1184))`, a 1,237-byte message. Because it
/// also covers the ML-KEM public key, neither the server nor a man in the middle can swap in its own pk_M. The outer layer does not accept v2 signatures
pub const ENC_KEY_V3_TAG: &[u8] = b"gori-core/enc-key-v3\0";

fn tagged(tag: &[u8], body: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(tag.len() + 32);
    m.extend_from_slice(tag);
    m.extend_from_slice(body);
    m
}

/// Message signed for device certificate v2
pub fn device_cert_message(device_pub: &[u8; 32]) -> Vec<u8> {
    tagged(DEVICE_CERT_TAG, device_pub)
}

/// Message signed for encryption key signature v2
pub fn enc_key_message(enc_pub: &[u8; 32]) -> Vec<u8> {
    tagged(ENC_KEY_TAG, enc_pub)
}

/// Message signed for encryption key signature v3. `hek` is an already validated HEK (pk_M ‖ pk_X); the message puts pk_X first
pub fn enc_key_v3_message(hek: &[u8; pq::HEK_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ENC_KEY_V3_TAG.len() + pq::HEK_LEN);
    m.extend_from_slice(ENC_KEY_V3_TAG);
    m.extend_from_slice(&hek[pq::PK_M_LEN..]);
    m.extend_from_slice(&hek[..pq::PK_M_LEN]);
    m
}

/// Compares two 32-byte values without data-dependent branches, even when they are not secret (used to compare the private
/// key held in a slot with a recovered key)
pub fn same32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn random_secret(rng: &mut dyn CryptoRngCore) -> Secret32 {
    let mut s = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(s.as_mut());
    s
}

pub fn random_array<const N: usize>(rng: &mut dyn CryptoRngCore) -> [u8; N] {
    let mut a = [0u8; N];
    rng.fill_bytes(&mut a);
    a
}

pub fn to_array32(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidArgument)
}

// ── XChaCha20-Poly1305 ──

pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        // Fails only above the length limit (2^38 bytes). Callers already split large inputs into chunks
        .expect("xchacha20poly1305 encrypt")
}

pub fn open(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

// ── HKDF-SHA256 ──

pub fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Secret32 {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut()).expect("32 bytes is a valid HKDF length");
    out
}

// ── X25519 ──

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*secret);
    PublicKey::from(&s).to_bytes()
}

/// Whether u is canonically encoded: bit 255 is 0 and u < p = 2^255 - 19
fn x25519_canonical(u: &[u8; 32]) -> bool {
    if u[31] & 0x80 != 0 {
        return false;
    }
    // With bit 255 clear, the only values with u ≥ p are p..2^255-1 (first byte ≥ 0xed, middle bytes 0xff, last byte 0x7f)
    !(u[31] == 0x7f && u[1..31].iter().all(|&b| b == 0xff) && u[0] >= 0xed)
}

/// Validates an X25519 public key that something is about to be sealed to (seal_to, reseal_share, prepare_recovery). Every
/// honestly generated key passes.
///
/// - Canonical encoding: bit 255 is 0 and u < p. Otherwise the sender's HKDF salt would differ from the recipient's (which
///   uses its own canonical public key) and nobody could open the envelope
/// - The point is on the curve (not the twist) and is not of small order. Small-order points would also be caught by the
///   contributory shared-secret check, but they are rejected here first
///
/// The return value is a **class representative used to decide whether two keys belong to the same holder**, u([8]P).
/// Variants with bit 255 set, with u + p, or with a torsion point added all give the same DH value for the same private key
/// (a clamped scalar is a multiple of 8). Comparing representatives treats all of them as one key, so a single holder cannot
/// be given two recovery shares
pub fn x25519_key_class(pubkey: &[u8]) -> Result<[u8; 32], Error> {
    let u = to_array32(pubkey)?;
    if !x25519_canonical(&u) {
        return Err(Error::WeakKey);
    }
    // None if u lies on the twist (including u = -1)
    let p = MontgomeryPoint(u).to_edwards(0).ok_or(Error::WeakKey)?;
    if p.is_small_order() {
        return Err(Error::WeakKey);
    }
    Ok(p.mul_by_cofactor().to_montgomery().to_bytes())
}

/// Rejects a non-contributory (all-zero) shared secret, as noble does
pub fn x25519_shared(secret: &[u8; 32], their_pub: &[u8]) -> Result<Secret32, Error> {
    let their = PublicKey::from(to_array32(their_pub)?);
    let s = StaticSecret::from(*secret);
    let shared = s.diffie_hellman(&their);
    if !shared.was_contributory() {
        return Err(Error::WeakKey);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

// ── Ed25519 ──

pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// Whether this is a strict Ed25519 public key. Every honestly generated public key (seed → clamped scalar × B) passes.
///
/// - **Canonical encoding**: decompressing and recompressing gives the same bytes (rejects y ≥ p, and '-0', i.e. x = 0 with
///   the sign bit set)
/// - **Not of small order**: for a key such as the identity (01 00..00), the single signature R = identity, S = 0 would verify
///   for every message
/// - **Torsion-free** (in the order-ℓ subgroup): for mixed-order keys, cofactored verification (noble, ZIP-215) and
///   cofactorless verification (dalek, WebCrypto) can disagree
pub fn ed25519_key_strict(pubkey: &[u8]) -> Option<VerifyingKey> {
    let pk = <[u8; 32]>::try_from(pubkey).ok()?;
    let vk = VerifyingKey::from_bytes(&pk).ok()?;
    let point = vk.to_edwards();
    if point.compress().to_bytes() != pk || point.is_small_order() || !point.is_torsion_free() {
        return None;
    }
    Some(vk)
}

/// Strict verification: the public key must pass [`ed25519_key_strict`] and the signature must pass `verify_strict` (S is
/// canonical, R is not of small order, and R is recomputed and compared as bytes; since the public key is torsion-free, R must
/// also be canonical and torsion-free to match). Under these rules the cofactored and cofactorless equations always agree
pub fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Some(vk) = ed25519_key_strict(pubkey) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

// ── Envelope: ephPub(32) ‖ nonce(24) ‖ XChaCha20-Poly1305(wrapKey, payload) ──

pub fn seal_bytes(
    rng: &mut dyn CryptoRngCore,
    payload: &[u8],
    recipient_pub: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, Error> {
    let recipient = to_array32(recipient_pub)?;
    x25519_key_class(&recipient)?;
    let eph = random_secret(rng);
    let eph_pub = x25519_public(&eph);
    let shared = x25519_shared(&eph, &recipient)?;
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&eph_pub);
    salt[32..].copy_from_slice(&recipient);
    let wrap_key = hkdf32(shared.as_ref(), Some(&salt), info);
    let nonce: [u8; NONCE_LEN] = random_array(rng);
    let body = seal(&wrap_key, &nonce, &[], payload);
    let mut out = Vec::with_capacity(32 + NONCE_LEN + body.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens an envelope. Format checks are done by the caller (envelopes and shares have different length rules)
pub fn open_bytes(envelope: &[u8], my_secret: &[u8; 32], info: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if envelope.len() < 32 + NONCE_LEN + TAG_LEN {
        return None;
    }
    let eph_pub = &envelope[..32];
    let nonce = &envelope[32..56];
    let body = &envelope[56..];
    let my_pub = x25519_public(my_secret);
    let shared = x25519_shared(my_secret, eph_pub).ok()?;
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(&my_pub);
    let wrap_key = hkdf32(shared.as_ref(), Some(&salt), info);
    open(&wrap_key, nonce, &[], body)
}

// ── Outer envelope v2 (hybrid): 0x02 ‖ ct(1120) ‖ nonce(24) ‖ XChaCha20-Poly1305(wrap_key, kid(8) ‖ payload, aad = 0x02 ‖ ct) ──
//
// The envelope does not reveal its recipient: the cleartext header is only the version byte and ct (ct_X is a fresh ephemeral
// public key for every seal, and the ML-KEM ciphertext hides the recipient's public key). The recipient key identifier kid exists
// only **inside** the AEAD (it lets a user with several devices confirm "this was sent to this particular key of mine").
// wrap_key = HKDF-SHA256(ss, no salt, context ‖ 0x00 ‖ version); ss already binds ct_X and pk_X

/// Outer envelope version byte
pub const OUTER_V2: u8 = 0x02;
/// Length of the recipient key identifier
pub const KID_LEN: usize = 8;
/// kid = SHA-256(KID_TAG ‖ HEK)[0..8]
pub const KID_TAG: &[u8] = b"gori-pq/kid-v1\0";
/// Outer envelope overhead, excluding the payload = 1 + 1120 + 24 + 8 + 16 = 1,169
pub const OUTER_OVERHEAD: usize = 1 + pq::CT_LEN + NONCE_LEN + KID_LEN + TAG_LEN;

/// Recipient key identifier
pub fn kid(hek: &[u8; pq::HEK_LEN]) -> [u8; KID_LEN] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(KID_TAG);
    h.update(hek);
    let full = h.finalize();
    let mut out = [0u8; KID_LEN];
    out.copy_from_slice(&full[..KID_LEN]);
    out
}

fn outer_wrap_key(ss: &[u8; 32], info: &[u8]) -> Secret32 {
    let mut full = Vec::with_capacity(info.len() + 2);
    full.extend_from_slice(info);
    full.push(0);
    full.push(OUTER_V2);
    hkdf32(ss, None, &full)
}

/// Seals with outer envelope v2. `to` is a recipient key that has passed [`pq::RecipientKey::parse`]. Randomness is drawn in the
/// order eseed(64), then nonce(24) (the test vectors depend on this order)
pub fn seal_bytes_v2(
    rng: &mut dyn CryptoRngCore,
    payload: &[u8],
    to: &pq::RecipientKey,
    info: &[u8],
) -> Result<Vec<u8>, Error> {
    let (ct, ss) = to.encapsulate(rng)?;
    let wrap_key = outer_wrap_key(&ss, info);
    let nonce: [u8; NONCE_LEN] = random_array(rng);
    let mut aad = Vec::with_capacity(1 + pq::CT_LEN);
    aad.push(OUTER_V2);
    aad.extend_from_slice(&ct);
    let mut inner = Zeroizing::new(Vec::with_capacity(KID_LEN + payload.len()));
    inner.extend_from_slice(&kid(to.hek()));
    inner.extend_from_slice(payload);
    let body = seal(&wrap_key, &nonce, &aad, &inner);
    let mut out = aad;
    out.reserve_exact(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens outer envelope v2 and returns the payload. Length rules are checked by the caller (each purpose has a fixed payload
/// length). `BadEnvelope` if the version is not 0x02 or the input is too short; `NotForMe` if it does not open (including a ct
/// whose ML-KEM part alone is wrong, through implicit rejection) or if the inner kid does not match my HEK
pub fn open_bytes_v2(envelope: &[u8], keys: &pq::EncKeys, info: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if envelope.len() < OUTER_OVERHEAD || envelope[0] != OUTER_V2 {
        return Err(Error::BadEnvelope);
    }
    let head = 1 + pq::CT_LEN;
    let ss = keys.decapsulate(&envelope[1..head]).map_err(|e| if e == Error::WeakKey { Error::NotForMe } else { e })?;
    let wrap_key = outer_wrap_key(&ss, info);
    let inner = open(&wrap_key, &envelope[head..head + NONCE_LEN], &envelope[..head], &envelope[head + NONCE_LEN..])
        .ok_or(Error::NotForMe)?;
    let mine = kid(&keys.hek());
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&inner[..KID_LEN], &mine[..])) {
        return Err(Error::NotForMe);
    }
    Ok(Zeroizing::new(inner[KID_LEN..].to_vec()))
}

// ── PIN hash (scrypt, RFC 7914) ──
//
// Used for the app's PIN hash (N=2^14, r=8, p=1, 32-byte output). The output is byte-for-byte identical to @noble/hashes
// (tests/scrypt.rs). Does not touch core state.

/// Allowed log₂N range: 2^10 (1,024) to 2^20. Outside it gives `InvalidArgument`
pub const SCRYPT_LOG_N: std::ops::RangeInclusive<u32> = 10..=20;
/// Allowed r range
pub const SCRYPT_R: std::ops::RangeInclusive<u32> = 1..=16;
/// Allowed p range
pub const SCRYPT_P: std::ops::RangeInclusive<u32> = 1..=4;
/// Allowed output length range (bytes)
pub const SCRYPT_LEN: std::ops::RangeInclusive<usize> = 16..=64;

/// scrypt (RFC 7914): fills all of `out`. Returns `InvalidArgument` if any parameter is out of range (nothing is written)
pub fn scrypt(password: &[u8], salt: &[u8], log_n: u32, r: u32, p: u32, out: &mut [u8]) -> Result<(), Error> {
    if !SCRYPT_LOG_N.contains(&log_n) || !SCRYPT_R.contains(&r) || !SCRYPT_P.contains(&p) || !SCRYPT_LEN.contains(&out.len()) {
        return Err(Error::InvalidArgument);
    }
    let params = scrypt::Params::new(log_n as u8, r, p, out.len()).map_err(|_| Error::InvalidArgument)?;
    scrypt::scrypt(password, salt, &params, out).map_err(|_| Error::InvalidArgument)
}
