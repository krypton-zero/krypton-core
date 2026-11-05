//! Post-quantum hybrid keys: the encryption seed (X25519 + ML-KEM-768, X-Wing style) and the identity seed
//! (Ed25519 + ML-DSA-65).
//!
//! The post-quantum primitives come from the RustCrypto `ml-kem` and `ml-dsa` crates. The construction is hybrid: it
//! stays secure as long as either the classical (X25519, Ed25519) or the post-quantum (ML-KEM, ML-DSA) component holds,
//! so it is never weaker than the classical scheme alone.
//!
//! ## Encryption seed (identical to X-Wing key generation, draft-connolly-cfrg-xwing-kem-06)
//!
//! ```text
//! seed sk(32) → SHAKE256(sk, 96) = ML-KEM seed d‖z (64) ‖ X25519 secret (32)
//! HEK(1216)   = pk_M(1184) ‖ pk_X(32)
//! ct(1120)    = ct_M(1088) ‖ ct_X(32)        (ct_X: a fresh ephemeral X25519 public key per encapsulation)
//! ss(32)      = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")
//! ```
//!
//! The derivation never goes the other way (ML-KEM seed from the X25519 secret): an attacker who recovers the X25519
//! secret with Shor's algorithm would then obtain the ML-KEM key as well.
//!
//! ## Identity seed
//!
//! ```text
//! isd(32) → SHAKE256("gori-core/id-seed-v1\0" ‖ isd, 64) = Ed25519 secret(32) ‖ ML-DSA-65 seed ξ(32)
//! pk_D(1952) = ML-DSA-65.KeyGen_internal(ξ)
//! dh(32)     = SHA3-256("gori-core/pq-sig-id-v1\0" ‖ pk_D)
//! ds(64)     = Ed25519(ik, "gori-core/pq-sig-bind-v1\0" ‖ ik ‖ dh)
//! dq(3309)   = ML-DSA-65.Sign(sk_D, "gori-core/pq-sig-bind-v1\0" ‖ ik ‖ dh, ctx = "gori-core")   (pure ML-DSA, hedged)
//! ```
//!
//! Secret material (expanded seeds, the ML-KEM decapsulation key, the ML-DSA signing key, ss) stays inside the core and is
//! wiped as soon as it is dropped (`Zeroizing` and the crates' `zeroize` feature). ML-KEM and ML-DSA keys are never
//! stored: they are re-derived from the seed on every use (a few milliseconds).

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature as DsaSignature, VerifyingKey as DsaVerifyingKey};
use ml_kem::array::Array;
use ml_kem::{Decapsulate, KeyExport, MlKem768};
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, Secret32};
use crate::error::Error;

type DecapsulationKey = ml_kem::DecapsulationKey<MlKem768>;
type EncapsulationKey = ml_kem::EncapsulationKey<MlKem768>;
type DsaSigningKey = ml_dsa::SigningKey<MlDsa65>;

/// ML-KEM-768 public key (FIPS 203 ek)
pub const PK_M_LEN: usize = 1184;
/// X25519 public key
pub const PK_X_LEN: usize = 32;
/// Hybrid public key HEK = pk_M ‖ pk_X (X-Wing order)
pub const HEK_LEN: usize = PK_M_LEN + PK_X_LEN; // 1216
/// ML-KEM-768 ciphertext
pub const CT_M_LEN: usize = 1088;
/// Encapsulation ciphertext ct = ct_M ‖ ct_X
pub const CT_LEN: usize = CT_M_LEN + PK_X_LEN; // 1120
/// Encapsulation randomness: ML-KEM m(32) ‖ ephemeral X25519 secret(32), the eseed of X-Wing `EncapsulateDerand`
pub const ESEED_LEN: usize = 64;
/// X-Wing combiner label `\.//^\`
pub const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

/// ML-DSA-65 public key
pub const PK_D_LEN: usize = 1952;
/// ML-DSA-65 signature
pub const DSA_SIG_LEN: usize = 3309;
/// Domain tag for expanding the identity seed into both the Ed25519 secret and the ML-DSA seed ξ
pub const ID_SEED_TAG: &[u8] = b"gori-core/id-seed-v1\0";
/// dh = SHA3-256(this tag ‖ pk_D)
pub const PQ_SIG_ID_TAG: &[u8] = b"gori-core/pq-sig-id-v1\0";
/// The message signed by ds and dq = this tag ‖ ik(32) ‖ dh(32)
pub const PQ_SIG_BIND_TAG: &[u8] = b"gori-core/pq-sig-bind-v1\0";
/// Context string for ML-DSA signatures (FIPS 204 ctx)
pub const DSA_CONTEXT: &[u8] = b"gori-core";

// ── SHAKE256 ──

fn shake256<const N: usize>(parts: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = Zeroizing::new([0u8; N]);
    h.finalize_xof().read(out.as_mut());
    out
}

// ── Encryption seed ──

/// Key set derived from an encryption seed. Secrets are wiped on drop (the ML-KEM decapsulation key through the crate's `zeroize`, the X25519 secret through `Zeroizing`)
pub struct EncKeys {
    dk_m: DecapsulationKey,
    x_secret: Secret32,
    pk_x: [u8; PK_X_LEN],
}

impl EncKeys {
    /// Expands the seed, identical to X-Wing key generation (`SHAKE256(sk, 96)`)
    pub fn from_seed(seed: &[u8; 32]) -> EncKeys {
        let expanded = shake256::<96>(&[seed]);
        let mut d_z = Zeroizing::new(Array::<u8, _>::default());
        d_z.copy_from_slice(&expanded[..64]);
        let dk_m = DecapsulationKey::from_seed(*d_z);
        let mut x_secret = Zeroizing::new([0u8; 32]);
        x_secret.copy_from_slice(&expanded[64..]);
        let pk_x = crypto::x25519_public(&x_secret);
        EncKeys { dk_m, x_secret, pk_x }
    }

    /// X25519 public key (32), the classical "encryption public key". The inner envelope (104 B) is sealed to this key
    pub fn pk_x(&self) -> [u8; PK_X_LEN] {
        self.pk_x
    }

    /// X25519 secret, lent only within the crate
    #[allow(dead_code)]
    pub(crate) fn x_secret(&self) -> &[u8; 32] {
        &self.x_secret
    }

    /// ML-KEM-768 public key (1184)
    pub fn pk_m(&self) -> [u8; PK_M_LEN] {
        let mut out = [0u8; PK_M_LEN];
        out.copy_from_slice(&self.dk_m.encapsulation_key().to_bytes());
        out
    }

    /// Hybrid public key HEK (1216) = pk_M ‖ pk_X
    pub fn hek(&self) -> [u8; HEK_LEN] {
        let mut out = [0u8; HEK_LEN];
        out[..PK_M_LEN].copy_from_slice(&self.pk_m());
        out[PK_M_LEN..].copy_from_slice(&self.pk_x);
        out
    }

    /// Decapsulates. ct must be exactly 1120 bytes. A non-contributory X25519 component (small-order ct_X) is rejected;
    /// honest encapsulation never produces one (plain X-Wing accepts it, this core rejects it just as the classical
    /// envelope does). An invalid ML-KEM ciphertext yields an unrelated ss_M through FIPS 203 implicit rejection, so the
    /// combined secret differs and the AEAD decides whether the envelope opens
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Secret32, Error> {
        if ct.len() != CT_LEN {
            return Err(Error::BadEnvelope);
        }
        let ct_m: ml_kem::Ciphertext<MlKem768> = Array::try_from(&ct[..CT_M_LEN]).map_err(|_| Error::BadEnvelope)?;
        let ct_x: [u8; 32] = crypto::to_array32(&ct[CT_M_LEN..])?;
        let ss_m = Zeroizing::new(self.dk_m.decapsulate(&ct_m));
        let ss_x = crypto::x25519_shared(&self.x_secret, &ct_x)?;
        Ok(combiner(ss_m.as_slice(), &ss_x, &ct_x, &self.pk_x))
    }
}

/// Derives only the X25519 secret from an encryption seed, skipping ML-KEM key generation (for the 32-byte public key,
/// opening inner envelopes and legacy guardian recovery). Identical to the X25519 half of [`EncKeys::from_seed`]
pub fn x_secret_from_seed(seed: &[u8; 32]) -> Secret32 {
    let expanded = shake256::<96>(&[seed]);
    let mut x = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&expanded[64..]);
    x
}

/// X-Wing combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")`
pub fn combiner(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Secret32 {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    out
}

/// A recipient's hybrid public key that has passed validation
pub struct RecipientKey {
    ek_m: EncapsulationKey,
    pk_x: [u8; PK_X_LEN],
    hek: [u8; HEK_LEN],
}

impl RecipientKey {
    /// Validates a HEK (1216): the length (otherwise `NeedHybridKey`, which stops an attempt to seal the outer layer to a
    /// 32-byte X25519 key), pk_X with [`crypto::x25519_key_class`] (canonical encoding, on the curve, not small order), and
    /// pk_M with the FIPS 203 §7.2 modulus check (`EncapsulationKey::new` in `ml-kem` decodes the 12-bit coefficients and
    /// checks that re-encoding gives the same bytes; ml-kem 0.3.3 src/pke.rs:168). If either public key fails, `WeakKey`
    pub fn parse(hek: &[u8]) -> Result<RecipientKey, Error> {
        if hek.len() != HEK_LEN {
            return Err(Error::NeedHybridKey);
        }
        let pk_x = crypto::to_array32(&hek[PK_M_LEN..])?;
        crypto::x25519_key_class(&pk_x)?;
        let enc = Array::try_from(&hek[..PK_M_LEN]).map_err(|_| Error::WeakKey)?;
        let ek_m = EncapsulationKey::new(&enc).map_err(|_| Error::WeakKey)?;
        let mut whole = [0u8; HEK_LEN];
        whole.copy_from_slice(hek);
        Ok(RecipientKey { ek_m, pk_x, hek: whole })
    }

    pub fn hek(&self) -> &[u8; HEK_LEN] {
        &self.hek
    }

    /// Deterministic encapsulation, X-Wing `EncapsulateDerand(pk, eseed)`: the first 32 bytes of eseed are the ML-KEM m,
    /// the last 32 the ephemeral X25519 secret. The caller draws the randomness from the core's RNG
    /// ([`RecipientKey::encapsulate`]). Outside test vectors an eseed must never be used twice
    pub fn encapsulate_derand(&self, eseed: &[u8; ESEED_LEN]) -> Result<([u8; CT_LEN], Secret32), Error> {
        let mut m = Zeroizing::new(Array::<u8, _>::default());
        m.copy_from_slice(&eseed[..32]);
        let (ct_m, ss_m) = self.ek_m.encapsulate_deterministic(&m);
        let ss_m = Zeroizing::new(ss_m);
        let mut eph = Zeroizing::new([0u8; 32]);
        eph.copy_from_slice(&eseed[32..]);
        let ct_x = PublicKey::from(&StaticSecret::from(*eph)).to_bytes();
        let ss_x = crypto::x25519_shared(&eph, &self.pk_x)?;
        let ss = combiner(ss_m.as_slice(), &ss_x, &ct_x, &self.pk_x);
        let mut ct = [0u8; CT_LEN];
        ct[..CT_M_LEN].copy_from_slice(&ct_m);
        ct[CT_M_LEN..].copy_from_slice(&ct_x);
        Ok((ct, ss))
    }

    /// Encapsulates, drawing 64 random bytes from `rng`
    pub fn encapsulate(&self, rng: &mut dyn CryptoRngCore) -> Result<([u8; CT_LEN], Secret32), Error> {
        let mut eseed = Zeroizing::new([0u8; ESEED_LEN]);
        rng.fill_bytes(eseed.as_mut());
        self.encapsulate_derand(&eseed)
    }
}

// ── Identity seed ──

/// Ed25519 secret (32) and ML-DSA seed ξ (32) derived from an identity seed. Wiped on drop
pub struct IdSeeds {
    pub ed_secret: Secret32,
    xi: Secret32,
}

impl IdSeeds {
    pub fn from_seed(isd: &[u8; 32]) -> IdSeeds {
        let expanded = shake256::<64>(&[ID_SEED_TAG, isd]);
        let mut ed_secret = Zeroizing::new([0u8; 32]);
        ed_secret.copy_from_slice(&expanded[..32]);
        let mut xi = Zeroizing::new([0u8; 32]);
        xi.copy_from_slice(&expanded[32..]);
        IdSeeds { ed_secret, xi }
    }

    /// Identity public key ik (Ed25519)
    pub fn ik(&self) -> [u8; 32] {
        crypto::ed25519_public(&self.ed_secret)
    }

    /// ML-DSA-65 signing key, wiped on drop by the crate (`zeroize` feature)
    fn dsa_key(&self) -> DsaSigningKey {
        let xi: Zeroizing<ml_dsa::Seed> = Zeroizing::new(Array::from(*self.xi));
        DsaSigningKey::from_seed(&xi)
    }

    /// ML-DSA-65 public key pk_D (1952)
    pub fn pk_d(&self) -> [u8; PK_D_LEN] {
        let mut out = [0u8; PK_D_LEN];
        out.copy_from_slice(&self.dsa_key().expanded_key().verifying_key().encode());
        out
    }

    /// Binding `(pk_D, dh, ds, dq)`. The 32 random bytes for dq (rnd in FIPS 204 hedged signing) come from `rng`
    pub fn binding(&self, rng: &mut dyn CryptoRngCore) -> PqSigBinding {
        let sk = self.dsa_key();
        let mut pk_d = [0u8; PK_D_LEN];
        pk_d.copy_from_slice(&sk.expanded_key().verifying_key().encode());
        let dh = pq_sig_id(&pk_d);
        let ik = self.ik();
        let msg = bind_message(&ik, &dh);
        let ds = crypto::ed25519_sign(&self.ed_secret, &msg);
        let mut rnd = Zeroizing::new(Array::<u8, _>::default());
        rng.fill_bytes(rnd.as_mut_slice());
        let dq = dsa_sign_with(&sk, &msg, DSA_CONTEXT, &rnd);
        PqSigBinding { pk_d, dh, ds, dq }
    }
}

/// FIPS 204 Algorithm 2 `ML-DSA.Sign` (pure, with context) using the given rnd: passes `M' = 0 ‖ |ctx| ‖ ctx ‖ M` to `Sign_internal`.
/// With rnd = 0 this equals the deterministic variant (tests/pq.rs compares it with `sign_deterministic`). ctx is at most 255 bytes (a caller-side constant)
fn dsa_sign_with(sk: &DsaSigningKey, msg: &[u8], ctx: &[u8], rnd: &ml_dsa::B32) -> [u8; DSA_SIG_LEN] {
    debug_assert!(ctx.len() <= 255);
    let head = [0u8, ctx.len() as u8];
    let sig = sk.expanded_key().sign_internal(&[&head, ctx, msg], rnd);
    let mut out = [0u8; DSA_SIG_LEN];
    out.copy_from_slice(&sig.encode());
    out
}

/// Test only: signs with a fixed rnd (so regenerated vectors are byte-identical). The core itself only uses [`IdSeeds::binding`]
#[doc(hidden)]
pub fn dsa_sign_for_tests(xi: &[u8; 32], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> [u8; DSA_SIG_LEN] {
    let sk = DsaSigningKey::from_seed(&Array::from(*xi));
    dsa_sign_with(&sk, msg, ctx, &Array::from(*rnd))
}

/// Test only: the 96-byte expanded encryption seed (d ‖ z ‖ X25519 secret), the value the zeroization tests watch for
#[doc(hidden)]
pub fn enc_expanded_for_tests(seed: &[u8; 32]) -> [u8; 96] {
    *shake256::<96>(&[seed])
}

/// Test only: the 64-byte expanded identity seed (Ed25519 secret ‖ ξ)
#[doc(hidden)]
pub fn id_expanded_for_tests(isd: &[u8; 32]) -> [u8; 64] {
    *shake256::<64>(&[ID_SEED_TAG, isd])
}

/// Test only: ξ → pk_D (ACVP keyGen)
#[doc(hidden)]
pub fn dsa_public_for_tests(xi: &[u8; 32]) -> [u8; PK_D_LEN] {
    let mut out = [0u8; PK_D_LEN];
    out.copy_from_slice(&DsaSigningKey::from_seed(&Array::from(*xi)).expanded_key().verifying_key().encode());
    out
}

/// dh = SHA3-256("gori-core/pq-sig-id-v1\0" ‖ pk_D)
pub fn pq_sig_id(pk_d: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, PQ_SIG_ID_TAG);
    Digest::update(&mut h, pk_d);
    h.finalize().into()
}

/// The message signed by ds and dq = "gori-core/pq-sig-bind-v1\0" ‖ ik ‖ dh
pub fn bind_message(ik: &[u8; 32], dh: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PQ_SIG_BIND_TAG.len() + 64);
    m.extend_from_slice(PQ_SIG_BIND_TAG);
    m.extend_from_slice(ik);
    m.extend_from_slice(dh);
    m
}

/// Pure ML-DSA-65 verification (FIPS 204 Algorithm 3 `ML-DSA.Verify`, with context). False on a wrong length or a malformed signature encoding
pub fn dsa_verify(pk_d: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = EncodedVerifyingKey::<MlDsa65>::try_from(pk_d) else { return false };
    let Ok(sig) = ml_dsa::EncodedSignature::<MlDsa65>::try_from(sig) else { return false };
    let Some(sig) = DsaSignature::<MlDsa65>::decode(&sig) else { return false };
    DsaVerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(msg, ctx, &sig)
}

/// Identity key binding. Public values only
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSigBinding {
    pub pk_d: [u8; PK_D_LEN],
    pub dh: [u8; 32],
    pub ds: [u8; 64],
    pub dq: [u8; DSA_SIG_LEN],
}

/// Verifies a binding presented by someone else (the same four steps as the server's registration check): (1) lengths,
/// (2) dh = SHA3-256(tag ‖ pk_D), (3) ds under ik (strict Ed25519), (4) dq under pk_D. False if any step fails
pub fn verify_binding(ik: &[u8], pk_d: &[u8], dh: &[u8], ds: &[u8], dq: &[u8]) -> bool {
    let (Ok(ik32), Ok(dh32)) = (<[u8; 32]>::try_from(ik), <[u8; 32]>::try_from(dh)) else { return false };
    if pk_d.len() != PK_D_LEN || ds.len() != 64 || dq.len() != DSA_SIG_LEN {
        return false;
    }
    if !crypto::same32(&pq_sig_id(pk_d), &dh32) {
        return false;
    }
    let msg = bind_message(&ik32, &dh32);
    crypto::ed25519_verify(&ik32, &msg, ds) && dsa_verify(pk_d, &msg, DSA_CONTEXT, dq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn hybrid_round_trip_and_sizes() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let keys = EncKeys::from_seed(&[7u8; 32]);
        let to = RecipientKey::parse(&keys.hek()).unwrap();
        let (ct, ss) = to.encapsulate(&mut rng).unwrap();
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(*keys.decapsulate(&ct).unwrap(), *ss);
        assert_eq!(RecipientKey::parse(&keys.pk_x()).err().map(|e| e as i32), Some(Error::NeedHybridKey as i32));
    }

    #[test]
    fn binding_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let id = IdSeeds::from_seed(&[9u8; 32]);
        let b = id.binding(&mut rng);
        assert!(verify_binding(&id.ik(), &b.pk_d, &b.dh, &b.ds, &b.dq));
        assert_eq!(b.pk_d, id.pk_d());
    }
}
