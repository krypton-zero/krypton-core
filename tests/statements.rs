//! Fixed vectors for statement v2 and strict verification: `tests/vectors/strict.json`.
//!
//! This file generates them from fixed inputs (normally it only regenerates them and compares with the file), and the
//! JavaScript reference implementation checks that it produces the same bytes and the same verdicts. Any other verifier
//! must reach the same verdicts on these vectors.
//! To change them: `GORI_WRITE_VECTORS=1 cargo test --test statements`.

use std::path::PathBuf;

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use gori_core::{crypto, pq, Core, Error, Slot};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct Statement {
    /// "deviceCert" | "encKey" | "encKeyV3"
    kind: String,
    /// The 32 bytes in the account slot: since the post-quantum version, the identity seed isd (the Ed25519 secret is
    /// derived with SHAKE256, src/pq.rs)
    account_seed: String,
    account_pub: String,
    /// Secret of the key being certified (device: Ed25519 seed, encryption: encryption seed)
    subject_secret: String,
    /// device: Ed25519 public key, encKey: pk_X(32), encKeyV3: HEK(1216 = pk_M ‖ pk_X)
    subject_pub: String,
    message: String,
    sig: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Case {
    name: String,
    #[serde(rename = "pub")]
    pubkey: String,
    msg: String,
    sig: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Named {
    name: String,
    #[serde(rename = "pub")]
    pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    generator: String,
    device_cert_tag: String,
    enc_key_tag: String,
    enc_key_v3_tag: String,
    reserved_prefix: String,
    statements: Vec<Statement>,
    /// Accepted by strict verification (honest signatures)
    accept: Vec<Case>,
    /// Must be rejected by strict verification; most pass at least one looser verifier (dalek's default verify, noble or
    /// WebCrypto)
    reject: Vec<Case>,
    /// Unusable as a recipient X25519 public key (seal_to, guardians)
    x25519_reject: Vec<Named>,
    /// Pairs of X25519 public keys treated as the same party (guardian deduplication)
    x25519_same: Vec<[String; 2]>,
}

fn x(b: &[u8]) -> String {
    hex::encode(b)
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn seeded(seed: u64) -> Core {
    Core::with_rng(Box::new(ChaCha20Rng::seed_from_u64(seed)))
}

fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let d = Sha512::digest(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&d[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&d[32..]);
    (Scalar::from_bytes_mod_order(a), prefix)
}

fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut d = Sha512::new();
    d.update(r);
    d.update(a);
    d.update(msg);
    Scalar::from_hash(d)
}

fn sig_bytes(r: &[u8; 32], s: &Scalar) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

fn generate() -> Fixture {
    let account_seed = [0x11u8; 32];
    let device_seed = [0x22u8; 32];
    let enc_secret = [0x33u8; 32];
    let mut me = seeded(1);
    let account_pub = me.load(Slot::Account, &account_seed).unwrap();
    let device_pub = me.load(Slot::Device, &device_seed).unwrap();
    let enc_pub = me.load(Slot::Enc, &enc_secret).unwrap();
    let hek = me.encryption_hybrid_key().unwrap();
    // The account slot holds the identity seed; raw Ed25519 operations (honest signature, mixed-order forgery) use the
    // secret derived from the seed
    let account_ed = *pq::IdSeeds::from_seed(&account_seed).ed_secret;
    let statements = vec![
        Statement {
            kind: "deviceCert".into(),
            account_seed: x(&account_seed),
            account_pub: x(&account_pub),
            subject_secret: x(&device_seed),
            subject_pub: x(&device_pub),
            message: x(&crypto::device_cert_message(&device_pub)),
            sig: x(&me.sign_device_certificate().unwrap()),
        },
        Statement {
            kind: "encKey".into(),
            account_seed: x(&account_seed),
            account_pub: x(&account_pub),
            subject_secret: x(&enc_secret),
            subject_pub: x(&enc_pub),
            message: x(&crypto::enc_key_message(&enc_pub)),
            sig: x(&me.sign_encryption_key().unwrap()),
        },
        Statement {
            kind: "encKeyV3".into(),
            account_seed: x(&account_seed),
            account_pub: x(&account_pub),
            subject_secret: x(&enc_secret),
            subject_pub: x(&hek),
            message: x(&crypto::enc_key_v3_message(&hek)),
            sig: x(&me.sign_encryption_key_v3().unwrap()),
        },
    ];

    let msg = b"gori-strict-v1".to_vec();
    let honest_sig = crypto::ed25519_sign(&account_ed, &msg);
    let accept = vec![
        Case { name: "honest".into(), pubkey: x(&account_pub), msg: x(&msg), sig: x(&honest_sig) },
        Case { name: "honest-empty-message".into(), pubkey: x(&device_pub), msg: String::new(), sig: x(&crypto::ed25519_sign(&device_seed, &[])) },
    ];

    let mut reject = Vec::new();
    // Identity key + universal signature (R = identity, S = 0)
    let mut universal = [0u8; 64];
    universal[0] = 1;
    let mut identity = [0u8; 32];
    identity[0] = 1;
    reject.push(Case { name: "identity-key-universal-sig".into(), pubkey: x(&identity), msg: x(&msg), sig: x(&universal) });
    // Non-canonical identity: y = p + 1, and the identity with its sign bit set (-0)
    let p_plus_1 = h32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    reject.push(Case { name: "noncanonical-identity-y-p-plus-1".into(), pubkey: x(&p_plus_1), msg: x(&msg), sig: x(&universal) });
    let mut neg0 = identity;
    neg0[31] |= 0x80;
    reject.push(Case { name: "identity-minus-zero".into(), pubkey: x(&neg0), msg: x(&msg), sig: x(&universal) });
    // Order-8 key: pick a message for which the universal signature passes (even under the cofactorless equation)
    let t8 = EIGHT_TORSION[1].compress().to_bytes();
    let vk8 = VerifyingKey::from_bytes(&t8).unwrap();
    let m8 = (0u8..=255)
        .map(|i| vec![i])
        .find(|m| vk8.verify_strict(m, &Signature::from_bytes(&universal)).is_err() && {
            use ed25519_dalek::Verifier;
            vk8.verify(m, &Signature::from_bytes(&universal)).is_ok()
        })
        .expect("a message the universal signature passes under the order-8 key");
    reject.push(Case { name: "order-8-key-universal-sig".into(), pubkey: x(&t8), msg: x(&m8), sig: x(&universal) });

    // S + ℓ on the honest key's signature
    let ell = h32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut s_plus = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = honest_sig[32 + i] as u16 + ell[i] as u16 + carry;
        s_plus[i] = v as u8;
        carry = v >> 8;
    }
    let mut mal = honest_sig;
    mal[32..].copy_from_slice(&s_plus);
    reject.push(Case { name: "s-plus-ell".into(), pubkey: x(&account_pub), msg: x(&msg), sig: x(&mal) });

    // Mixed-order R (honest key): the cofactored equation (noble, ZIP-215) accepts it, the cofactorless one rejects it
    let (a, prefix) = expand(&account_ed);
    let mut hr = Sha512::new();
    hr.update(prefix);
    hr.update(&msg);
    let r = Scalar::from_hash(hr);
    let rp = (r * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1]).compress().to_bytes();
    let k = challenge(&rp, &account_pub, &msg);
    reject.push(Case { name: "mixed-order-r".into(), pubkey: x(&account_pub), msg: x(&msg), sig: x(&sig_bytes(&rp, &(r + k * a))) });

    // Mixed-order key A' = aB + T, with a signature searched so that the cofactorless equation also passes: dalek's
    // verify and verify_strict both accept it
    let a_mixed = (a * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1]).compress().to_bytes();
    let vkm = VerifyingKey::from_bytes(&a_mixed).unwrap();
    let mixed_sig = (1u64..)
        .flat_map(|n| (0..8usize).map(move |j| (n, j)))
        .map(|(n, j)| {
            let r = Scalar::from(n);
            let rb = (r * ED25519_BASEPOINT_POINT + EIGHT_TORSION[j]).compress().to_bytes();
            sig_bytes(&rb, &(r + challenge(&rb, &a_mixed, &msg) * a))
        })
        .find(|sg| vkm.verify_strict(&msg, &Signature::from_bytes(sg)).is_ok())
        .unwrap();
    reject.push(Case { name: "mixed-order-key".into(), pubkey: x(&a_mixed), msg: x(&msg), sig: x(&mixed_sig) });

    // Signatures for another purpose: an old (v1) encryption key signature does not pass as a device certificate v2, and
    // v2 statements do not pass as each other
    let legacy_enc = crypto::ed25519_sign(&account_ed, &enc_pub);
    reject.push(Case {
        name: "legacy-enc-sig-as-device-cert-v2".into(),
        pubkey: x(&account_pub),
        msg: x(&crypto::device_cert_message(&enc_pub)),
        sig: x(&legacy_enc),
    });
    reject.push(Case {
        name: "enc-key-v2-as-device-cert-v2".into(),
        pubkey: x(&account_pub),
        msg: x(&crypto::device_cert_message(&enc_pub)),
        sig: statements[1].sig.clone(),
    });
    // v3 (a signature covering the HEK) does not pass as a v2 statement, nor a v2 signature as a v3 statement; the outer
    // layer does not accept v2
    reject.push(Case {
        name: "enc-key-v3-as-enc-key-v2".into(),
        pubkey: x(&account_pub),
        msg: x(&crypto::enc_key_message(&enc_pub)),
        sig: statements[2].sig.clone(),
    });
    reject.push(Case {
        name: "enc-key-v2-as-enc-key-v3".into(),
        pubkey: x(&account_pub),
        msg: x(&crypto::enc_key_v3_message(&hek)),
        sig: statements[1].sig.clone(),
    });

    // X25519
    let mut x25519_reject = Vec::new();
    for (name, u) in [
        ("zero", h32("0000000000000000000000000000000000000000000000000000000000000000")),
        ("one", h32("0100000000000000000000000000000000000000000000000000000000000000")),
        ("order-8", h32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")),
        ("p-minus-1", h32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")),
        ("p", h32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")),
    ] {
        x25519_reject.push(Named { name: name.into(), pubkey: x(&u) });
    }
    let mut hi = enc_pub;
    hi[31] |= 0x80;
    x25519_reject.push(Named { name: "honest-key-high-bit".into(), pubkey: x(&hi) });
    let twist = (2u8..)
        .map(|u0| {
            let mut u = [0u8; 32];
            u[0] = u0;
            u
        })
        .find(|u| MontgomeryPoint(*u).to_edwards(0).is_none())
        .unwrap();
    x25519_reject.push(Named { name: "twist".into(), pubkey: x(&twist) });

    let torsioned = (MontgomeryPoint(enc_pub).to_edwards(0).unwrap() + EIGHT_TORSION[1]).to_montgomery().to_bytes();
    let x25519_same = vec![[x(&enc_pub), x(&torsioned)]];

    Fixture {
        generator: "gori-core (Rust) tests/statements.rs".into(),
        device_cert_tag: x(crypto::DEVICE_CERT_TAG),
        enc_key_tag: x(crypto::ENC_KEY_TAG),
        enc_key_v3_tag: x(crypto::ENC_KEY_V3_TAG),
        reserved_prefix: x(crypto::CORE_STATEMENT_PREFIX),
        statements,
        accept,
        reject,
        x25519_reject,
        x25519_same,
    }
}

fn check(f: &Fixture) {
    assert_eq!(h(&f.device_cert_tag), b"gori-core/device-cert-v2\0");
    assert_eq!(h(&f.enc_key_tag), b"gori-core/enc-key-v2\0");
    assert_eq!(h(&f.enc_key_v3_tag), b"gori-core/enc-key-v3\0");
    for s in &f.statements {
        let mut c = seeded(9);
        assert_eq!(x(&c.load(Slot::Account, &h(&s.account_seed)).unwrap()), s.account_pub);
        let sig = match s.kind.as_str() {
            "deviceCert" => {
                assert_eq!(x(&c.load(Slot::Device, &h(&s.subject_secret)).unwrap()), s.subject_pub);
                assert_eq!(x(&crypto::device_cert_message(&h32(&s.subject_pub))), s.message);
                c.sign_device_certificate().unwrap()
            }
            "encKey" => {
                assert_eq!(x(&c.load(Slot::Enc, &h(&s.subject_secret)).unwrap()), s.subject_pub);
                assert_eq!(x(&crypto::enc_key_message(&h32(&s.subject_pub))), s.message);
                c.sign_encryption_key().unwrap()
            }
            "encKeyV3" => {
                c.load(Slot::Enc, &h(&s.subject_secret)).unwrap();
                let hek = c.encryption_hybrid_key().unwrap();
                assert_eq!(x(&hek), s.subject_pub);
                assert_eq!(x(&crypto::enc_key_v3_message(&hek)), s.message);
                c.sign_encryption_key_v3().unwrap()
            }
            k => panic!("{k}"),
        };
        assert_eq!(x(&sig), s.sig, "{}", s.kind);
        assert!(Core::verify(&h(&s.account_pub), &h(&s.message), &sig));
        // Ordinary signing cannot produce the same statement
        assert_eq!(c.sign(Slot::Account, &h(&s.message)).unwrap_err(), Error::ReservedStatement);
    }
    for c in &f.accept {
        assert!(Core::verify(&h(&c.pubkey), &h(&c.msg), &h(&c.sig)), "accept {}", c.name);
    }
    for c in &f.reject {
        assert!(!Core::verify(&h(&c.pubkey), &h(&c.msg), &h(&c.sig)), "reject {}", c.name);
    }
    let mut sender = seeded(10);
    let k = sender.create_content_key();
    for n in &f.x25519_reject {
        assert_eq!(sender.seal_inner(&k, &h(&n.pubkey)).unwrap_err(), Error::WeakKey, "x25519 {}", n.name);
    }
    for [a, b] in &f.x25519_same {
        assert_ne!(a, b);
        assert_eq!(crypto::x25519_key_class(&h(a)).unwrap(), crypto::x25519_key_class(&h(b)).unwrap());
    }
}

#[test]
fn strict_vectors_are_reproducible_and_hold() {
    let f = generate();
    check(&f);
    // Check that the reject vectors really pass a looser verifier (dalek's default verify or the cofactored equation), so
    // they are not vacuous
    let cofactored = |c: &Case| {
        let a = CompressedEdwardsY(h32(&c.pubkey)).decompress();
        let sig = h(&c.sig);
        let r = CompressedEdwardsY(sig[..32].try_into().unwrap()).decompress();
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()));
        match (a, r, s) {
            (Some(a), Some(r), Some(s)) => {
                let k = challenge(&sig[..32].try_into().unwrap(), &h32(&c.pubkey), &h(&c.msg));
                use curve25519_dalek::traits::IsIdentity;
                (r + k * a - s * ED25519_BASEPOINT_POINT).mul_by_cofactor().is_identity()
            }
            _ => false,
        }
    };
    let loose = |c: &Case| {
        use ed25519_dalek::Verifier;
        VerifyingKey::from_bytes(&h32(&c.pubkey))
            .map(|vk| vk.verify(&h(&c.msg), &Signature::from_bytes(&h(&c.sig).try_into().unwrap())).is_ok())
            .unwrap_or(false)
    };
    for c in &f.reject {
        if c.name.starts_with("legacy-") || c.name.starts_with("enc-key-v") || c.name == "s-plus-ell" {
            continue; // purpose and malleability: looser verification rejects these too (purpose cases differ in the statement)
        }
        assert!(loose(c) || cofactored(c), "{}: vector passes neither looser verifier", c.name);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/strict.json");
    if std::env::var("GORI_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, serde_json::to_string_pretty(&f).unwrap() + "\n").unwrap();
    }
    let on_disk: Fixture = serde_json::from_str(&std::fs::read_to_string(&path).expect("strict.json")).unwrap();
    assert_eq!(on_disk, f, "strict.json differs from the generator; regenerate it with GORI_WRITE_VECTORS=1");
}
