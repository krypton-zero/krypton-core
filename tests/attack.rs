//! Adversarial tests: each test mounts a concrete attack on the core (forged recovery bundles, malformed or
//! small-order keys, signature malleability, envelope and stream tampering, bad C ABI arguments) and checks
//! that it is rejected without changing any state.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io::Cursor;
use std::time::Instant;

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use gori_core::core::{ENVELOPE_LEN, MAX_GUARDIANS, SHARE_ENVELOPE_LEN};
use gori_core::ffi;
use gori_core::{crypto, shamir, stream, Core, Error, Slot};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512};

fn core(seed: u64) -> Core {
    Core::with_rng(Box::new(ChaCha20Rng::seed_from_u64(seed)))
}

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn x_secret(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// A core with an account key and an encryption key
fn member(seed: u64) -> (Core, [u8; 32]) {
    let mut c = core(seed);
    let acc = c.generate(Slot::Account);
    c.generate(Slot::Enc);
    (c, acc)
}

/// n guardians and their public keys
fn guardians(seed: u64, n: usize) -> (Vec<Core>, Vec<[u8; 32]>) {
    let mut gs: Vec<Core> = (0..n).map(|i| core(seed + i as u64)).collect();
    let gp = gs.iter_mut().map(|g| g.generate(Slot::Enc)).collect();
    (gs, gp)
}

/// The same key with bit 255 set (a non-canonical encoding)
fn hi_bit(p: &[u8; 32]) -> [u8; 32] {
    let mut q = *p;
    q[31] |= 0x80;
    q
}

/// The same key plus a torsion point (same DH value): u(P + T)
fn plus_torsion(p: &[u8; 32]) -> [u8; 32] {
    let ed = MontgomeryPoint(*p).to_edwards(0).unwrap();
    (ed + EIGHT_TORSION[1]).to_montgomery().to_bytes()
}

// ── Guardian keys in prepare_recovery ──

/// One guardian cannot be listed twice (same bytes, bit 255 set, u + p, or a torsion-shifted key) to hold k shares
#[test]
fn duplicate_and_noncanonical_guardians_rejected() {
    let (mut victim, _) = member(2);
    let (_, gp) = guardians(10, 3);
    let p = gp[0];
    // the same key twice
    assert_eq!(victim.prepare_recovery(&[p, p], 2).err(), Some(Error::DuplicateGuardian));
    assert_eq!(victim.prepare_recovery(&[gp[1], p, gp[2], p], 2).err(), Some(Error::DuplicateGuardian));
    // bit 255 set: non-canonical, rejected (same DH value)
    assert_eq!(victim.prepare_recovery(&[p, hi_bit(&p)], 2).err(), Some(Error::WeakKey));
    // u + p (a non-canonical u): only u < p is accepted
    let mut u_plus_p = [0xffu8; 32];
    u_plus_p[31] = 0x7f;
    u_plus_p[0] = 0xed; // p itself (= 0 mod p)
    assert_eq!(victim.prepare_recovery(&[p, u_plus_p], 2).err(), Some(Error::WeakKey));
    // the same key plus a torsion point: a canonical encoding but the same person (same representative u([8]P))
    let t = plus_torsion(&p);
    assert_ne!(t, p);
    assert_eq!(crypto::x25519_key_class(&t).unwrap(), crypto::x25519_key_class(&p).unwrap());
    assert_eq!(victim.prepare_recovery(&[p, t], 2).err(), Some(Error::DuplicateGuardian));
    // the user's own encryption key cannot be a guardian
    let mine = victim.public_key(Slot::Enc).unwrap();
    assert_eq!(victim.prepare_recovery(&[mine, p], 2).err(), Some(Error::InvalidArgument));
    // at least `threshold` distinct guardians are required
    assert!(victim.prepare_recovery(&gp, 2).is_ok());
    assert!(victim.prepare_recovery(&gp, 3).is_ok());
    assert_eq!(victim.prepare_recovery(&gp, 4).err(), Some(Error::TooFewGuardians));
}

#[test]
fn guardian_count_capped() {
    let (mut victim, _) = member(3);
    let (_, gp) = guardians(100, MAX_GUARDIANS + 1);
    assert!(victim.prepare_recovery(&gp[..MAX_GUARDIANS], 2).is_ok());
    assert_eq!(victim.prepare_recovery(&gp, 2).err(), Some(Error::BadShareCount));
}

// ── Re-sealing a share ──

/// reseal_share only seals to a strict X25519 key and only opens a share envelope of the exact length
#[test]
fn reseal_share_rejects_weak_targets_and_bad_lengths() {
    let (mut victim, _) = member(4);
    let (mut gs, gp) = guardians(20, 2);
    let kit = victim.prepare_recovery(&gp, 2).unwrap();
    let target = crypto::x25519_public(&x_secret(0x42));
    assert!(gs[0].reseal_share(&kit.guardian_shares[0], &target).is_ok());
    // small-order and non-canonical targets are refused
    assert_eq!(gs[0].reseal_share(&kit.guardian_shares[0], &hi_bit(&target)).unwrap_err(), Error::WeakKey);
    assert_eq!(gs[0].reseal_share(&kit.guardian_shares[0], &[0u8; 32]).unwrap_err(), Error::WeakKey);
    // a share envelope that is not 105 bytes is not opened
    assert_eq!(
        gs[0].reseal_share(&kit.guardian_shares[0][..104], &target).unwrap_err(),
        Error::BadShareEnvelope
    );
}

// ── Recovery never overwrites existing keys ──

/// Completing recovery with another person B's backup on a device that holds account A leaves A's keys intact
#[test]
fn complete_recovery_never_overwrites_existing_keys() {
    let (mut b, b_acc) = member(10);
    let (mut gs, gp) = guardians(11, 2);
    let kit = b.prepare_recovery(&gp, 2).unwrap();

    let (mut dev, a_acc) = member(13);
    let a_secret = dev.slot_secret(Slot::Account).unwrap();
    let a_enc = dev.slot_secret(Slot::Enc).unwrap();
    let (tmp, created) = dev.begin_recovery();
    assert!(created);
    let r: Vec<Vec<u8>> = (0..2).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap()).collect();

    // claiming the account is B: this device already holds A
    assert_eq!(dev.complete_recovery(&kit.backup, &r, &kit.server_share[..], &b_acc).unwrap_err(), Error::KeyConflict);
    // claiming it is A: the recovered key is not A
    assert_eq!(dev.complete_recovery(&kit.backup, &r, &kit.server_share[..], &a_acc).unwrap_err(), Error::AccountMismatch);
    assert_eq!(dev.slot_secret(Slot::Account), Some(a_secret));
    assert_eq!(dev.slot_secret(Slot::Enc), Some(a_enc));
    assert!(dev.has(Slot::Recovery), "on failure the temporary key remains");

    // a device that already holds the same key (e.g. the wrapper stored one key and was interrupted) completes
    let mut again = core(14);
    again.load(Slot::Account, &b.slot_secret(Slot::Account).unwrap()[..]).unwrap();
    let (tmp2, _) = again.begin_recovery();
    let r2: Vec<Vec<u8>> = (0..2).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp2).unwrap()).collect();
    let (a, _) = again.complete_recovery(&kit.backup, &r2, &kit.server_share[..], &b_acc).unwrap();
    assert_eq!(a, b_acc);
    assert_eq!(again.slot_secret(Slot::Enc), b.slot_secret(Slot::Enc));
}

/// A forged bundle sealed to the published temporary key (1-byte shares, a backup derived from HKDF(U) alone)
/// is rejected by length, and the slots stay unchanged
#[test]
fn forged_bundle_rejected_before_anything_is_stored() {
    let (mut dev, a_acc) = member(15);
    let a_secret = dev.slot_secret(Slot::Account).unwrap();
    let (tmp, _) = dev.begin_recovery();
    let mut r = rng(16);
    // each share is a lone x (T would be empty)
    let degenerate: Vec<Vec<u8>> =
        (1..=2u8).map(|x| crypto::seal_bytes(&mut r, &[x], &tmp, crypto::SHARE_INFO).unwrap()).collect();
    let u = [9u8; 32];
    let s = crypto::hkdf32(&u, None, crypto::SECRET_INFO);
    let evil_keys = [0x33u8; 64];
    let nonce = [1u8; 24];
    let mut backup = vec![1u8];
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&crypto::seal(&s, &nonce, &[], &evil_keys));
    assert_eq!(dev.complete_recovery(&backup, &degenerate, &u, &a_acc).unwrap_err(), Error::BadShareEnvelope);

    // a forgery with correct lengths (attacker-chosen T) is rejected: the recovered account is not the expected one
    let t = [0x44u8; 32];
    let coeffs = [0x55u8; 32];
    let shares = shamir::split(&t, 2, 2, &coeffs).unwrap();
    let forged: Vec<Vec<u8>> =
        shares.iter().map(|sh| crypto::seal_bytes(&mut r, sh, &tmp, crypto::SHARE_INFO).unwrap()).collect();
    assert!(forged.iter().all(|f| f.len() == SHARE_ENVELOPE_LEN));
    let mut ikm = t.to_vec();
    ikm.extend_from_slice(&u);
    let s2 = crypto::hkdf32(&ikm, None, crypto::SECRET_INFO);
    let evil_seed = [0x66u8; 32];
    let mut keys = evil_seed.to_vec();
    keys.extend_from_slice(&[0x77u8; 32]);
    let mut backup2 = vec![1u8];
    backup2.extend_from_slice(&nonce);
    backup2.extend_from_slice(&crypto::seal(&s2, &nonce, &[], &keys));
    assert_eq!(dev.complete_recovery(&backup2, &forged, &u, &a_acc).unwrap_err(), Error::AccountMismatch);
    assert_eq!(dev.slot_secret(Slot::Account), Some(a_secret));

    // on an empty device too: nothing is installed unless it is the expected account
    let mut fresh = core(17);
    let (tmp3, _) = fresh.begin_recovery();
    let forged3: Vec<Vec<u8>> =
        shares.iter().map(|sh| crypto::seal_bytes(&mut r, sh, &tmp3, crypto::SHARE_INFO).unwrap()).collect();
    assert_eq!(fresh.complete_recovery(&backup2, &forged3, &u, &a_acc).unwrap_err(), Error::AccountMismatch);
    assert!(!fresh.has(Slot::Account) && !fresh.has(Slot::Enc));
    assert!(fresh.has(Slot::Recovery));
}

#[test]
fn complete_recovery_input_bounds() {
    let (mut b, b_acc) = member(18);
    let (mut gs, gp) = guardians(19, 2);
    let kit = b.prepare_recovery(&gp, 2).unwrap();
    let mut fresh = core(21);
    let (tmp, _) = fresh.begin_recovery();
    let r: Vec<Vec<u8>> = (0..2).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap()).collect();
    let u = &kit.server_share[..];
    // U is exactly 32 bytes
    let mut long_u = u.to_vec();
    long_u.push(0);
    assert_eq!(fresh.complete_recovery(&kit.backup, &r, &long_u, &b_acc).unwrap_err(), Error::InvalidArgument);
    assert_eq!(fresh.complete_recovery(&kit.backup, &r, &u[..31], &b_acc).unwrap_err(), Error::InvalidArgument);
    // expected account key: 32 bytes and a strict Ed25519 key
    assert_eq!(fresh.complete_recovery(&kit.backup, &r, u, &b_acc[..31]).unwrap_err(), Error::InvalidArgument);
    let mut ident = [0u8; 32];
    ident[0] = 1;
    assert_eq!(fresh.complete_recovery(&kit.backup, &r, u, &ident).unwrap_err(), Error::InvalidArgument);
    // share count
    let none: [Vec<u8>; 0] = [];
    assert_eq!(fresh.complete_recovery(&kit.backup, &none, u, &b_acc).unwrap_err(), Error::NoShares);
    let many: Vec<Vec<u8>> = (0..=MAX_GUARDIANS).map(|i| r[i % 2].clone()).collect();
    assert_eq!(fresh.complete_recovery(&kit.backup, &many, u, &b_acc).unwrap_err(), Error::BadShareCount);
    // any share envelope that is not 105 bytes
    let mut padded = r.clone();
    padded[1].push(0);
    assert_eq!(fresh.complete_recovery(&kit.backup, &padded, u, &b_acc).unwrap_err(), Error::BadShareEnvelope);
    assert!(fresh.has(Slot::Recovery) && !fresh.has(Slot::Account));
    // valid bundle
    let (a, _) = fresh.complete_recovery(&kit.backup, &r, u, &b_acc).unwrap();
    assert_eq!(a, b_acc);
    assert!(!fresh.has(Slot::Recovery));
}

// ── X25519 ──

fn small_order_points() -> Vec<[u8; 32]> {
    let hexes = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let mut out = Vec::new();
    for h in hexes {
        let b: [u8; 32] = hex::decode(h).unwrap().try_into().unwrap();
        out.push(b);
        out.push(hi_bit(&b));
    }
    for t in EIGHT_TORSION.iter() {
        let u = t.to_montgomery().to_bytes();
        out.push(u);
        out.push(hi_bit(&u));
    }
    out
}

#[test]
fn small_order_twist_and_noncanonical_recipients_rejected() {
    let mut c = core(20);
    let mine = c.generate(Slot::Enc);
    let h = c.create_content_key();
    for p in small_order_points() {
        assert_eq!(c.seal_inner(&h, &p).unwrap_err(), Error::WeakKey, "seal_to {:02x?}", p);
        let mut env = vec![0u8; ENVELOPE_LEN];
        env[..32].copy_from_slice(&p);
        assert_eq!(c.open_inner(&env).unwrap_err(), Error::NotForMe);
    }
    // u on the twist: not a point on the curve (u^3 + A*u^2 + u is a non-square)
    let mut twists = 0;
    for u0 in 2u8..64 {
        let mut u = [0u8; 32];
        u[0] = u0;
        if MontgomeryPoint(u).to_edwards(0).is_none() {
            assert_eq!(c.seal_inner(&h, &u).unwrap_err(), Error::WeakKey, "twist u={u0}");
            twists += 1;
        }
    }
    assert!(twists > 0);
    // non-canonical encoding of an honest key
    assert_eq!(c.seal_inner(&h, &hi_bit(&mine)).unwrap_err(), Error::WeakKey);
    // the honest key itself is accepted
    assert!(c.seal_inner(&h, &mine).is_ok());
    // length
    assert_eq!(c.seal_inner(&h, &mine[..31]).unwrap_err(), Error::InvalidArgument);
}

#[test]
fn envelope_reencoding_and_tamper() {
    let mut sender = core(30);
    let mut recv = core(31);
    let rp = recv.generate(Slot::Enc);
    let rsk = *recv.slot_secret(Slot::Enc).unwrap();
    let h = sender.create_content_key();
    let env = sender.seal_inner(&h, &rp).unwrap();
    assert!(recv.open_inner(&env).is_ok());

    let eph: [u8; 32] = env[..32].try_into().unwrap();
    let dh = |u: &[u8; 32]| MontgomeryPoint(*u).mul_clamped(rsk).to_bytes();
    let mut e1 = env.clone();
    e1[31] ^= 0x80;
    let u1: [u8; 32] = e1[..32].try_into().unwrap();
    assert_eq!(dh(&u1), dh(&eph));
    assert_eq!(recv.open_inner(&e1).unwrap_err(), Error::NotForMe);
    let ed = MontgomeryPoint(eph).to_edwards(0).unwrap();
    for t in EIGHT_TORSION.iter().skip(1) {
        let u2 = (ed + t).to_montgomery().to_bytes();
        if u2 == eph {
            continue;
        }
        let mut e2 = env.clone();
        e2[..32].copy_from_slice(&u2);
        assert_eq!(recv.open_inner(&e2).unwrap_err(), Error::NotForMe);
    }
    for i in 0..env.len() {
        let mut e = env.clone();
        e[i] ^= 1;
        assert!(recv.open_inner(&e).is_err(), "byte {i}");
    }
    for len in [0, 1, 103, 105, 200] {
        let mut e = env.clone();
        e.resize(len, 0);
        assert_eq!(recv.open_inner(&e).unwrap_err(), Error::BadEnvelope);
    }
}

// ── GORS stream format ──

fn gors(key: &[u8; 32], seed: u64, exp: u8, len: usize) -> (Vec<u8>, Vec<u8>) {
    let pt: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
    let mut out = Vec::new();
    stream::encrypt(key, &mut rng(seed), exp, &mut Cursor::new(&pt), &mut out).unwrap();
    (pt, out)
}

fn dec(key: &[u8; 32], ct: &[u8]) -> (Result<u64, Error>, Vec<u8>) {
    let mut w = Vec::new();
    let r = stream::decrypt(key, &mut Cursor::new(ct), &mut w);
    (r, w)
}

#[test]
fn gors_cut_append_reorder_splice() {
    let key = [3u8; 32];
    let exp = 10u8;
    let full = (1usize << exp) + 16;
    let (pt, ct) = gors(&key, 1, exp, 5 * 1024);
    assert_eq!(dec(&key, &ct).1, pt);
    let chunk = |c: &[u8], i: usize| c[32 + i * full..32 + (i + 1) * full].to_vec();
    for k in 1..5 {
        assert_eq!(dec(&key, &ct[..32 + k * full]).0.unwrap_err(), Error::StreamAuth, "cut {k}");
    }
    let mut app = ct.clone();
    app.extend_from_slice(&chunk(&ct, 4));
    assert_eq!(dec(&key, &app).0.unwrap_err(), Error::StreamAuth);
    let mut sw = ct[..32].to_vec();
    for i in [0, 2, 1, 3, 4] {
        sw.extend_from_slice(&chunk(&ct, i));
    }
    assert_eq!(dec(&key, &sw).0.unwrap_err(), Error::StreamAuth);
    let (_, ct2) = gors(&key, 2, exp, 5 * 1024);
    let mut hdr = ct2[..32].to_vec();
    hdr.extend_from_slice(&ct[32..]);
    assert_eq!(dec(&key, &hdr).0.unwrap_err(), Error::StreamAuth);
}

#[test]
fn gors_header_checks() {
    let key = [5u8; 32];
    let base = gors(&key, 6, 16, 10).1;
    for (i, v) in [(0usize, b'X'), (4, 2), (4, 0), (5, 9), (5, 25), (5, 255), (6, 1), (7, 1)] {
        let mut c = base.clone();
        c[i] = v;
        assert_eq!(dec(&key, &c).0.unwrap_err(), Error::BadStream, "hdr[{i}]={v}");
    }
}

// ── Corrupted shares, resource limits ──

#[test]
fn invalid_extra_share_fails_without_changing_state() {
    let (mut v, v_acc) = member(40);
    let (mut gs, gp) = guardians(41, 3);
    let kit = v.prepare_recovery(&gp, 2).unwrap();
    let mut fresh = core(50);
    let (tmp, _) = fresh.begin_recovery();
    let r: Vec<Vec<u8>> = (0..2).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap()).collect();
    let mut fake_share = vec![3u8];
    fake_share.extend_from_slice(&[0xAA; 32]);
    let fake = crypto::seal_bytes(&mut rng(9), &fake_share, &tmp, crypto::SHARE_INFO).unwrap();
    let all = vec![r[0].clone(), r[1].clone(), fake];
    let u = &kit.server_share[..];
    assert_eq!(fresh.complete_recovery(&kit.backup, &all, u, &v_acc).unwrap_err(), Error::RecoveryFailed);
    assert!(!fresh.has(Slot::Account));
    assert!(fresh.has(Slot::Recovery));
    assert!(fresh.complete_recovery(&kit.backup, &all[..2], u, &v_acc).is_ok());
}

/// Oversized bundles are rejected by share count and length before any share is opened, and the largest allowed
/// bundle (MAX_GUARDIANS shares) still completes quickly
#[test]
fn oversized_bundles_rejected_quickly() {
    let (mut v, v_acc) = member(60);
    let mut fresh = core(61);
    let (tmp, _) = fresh.begin_recovery();
    let mut r = rng(62);
    let mut long_shares = Vec::new();
    for x in 1..=255u8 {
        let mut s = vec![x];
        let mut y = vec![0u8; 2000];
        r.fill_bytes(&mut y);
        s.extend_from_slice(&y);
        long_shares.push(crypto::seal_bytes(&mut r, &s, &tmp, crypto::SHARE_INFO).unwrap());
    }
    let backup = vec![1u8; 105];
    let u = [0u8; 32];
    let t0 = Instant::now();
    assert_eq!(fresh.complete_recovery(&backup, &long_shares, &u, &v_acc).unwrap_err(), Error::BadShareCount);
    assert_eq!(
        fresh.complete_recovery(&backup, &long_shares[..MAX_GUARDIANS], &u, &v_acc).unwrap_err(),
        Error::BadShareEnvelope
    );
    let rejected = t0.elapsed();

    // the largest allowed bundle: shares from all 16 guardians
    let (mut gs, gp) = guardians(200, MAX_GUARDIANS);
    let kit = v.prepare_recovery(&gp, MAX_GUARDIANS).unwrap();
    let all: Vec<Vec<u8>> =
        (0..MAX_GUARDIANS).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap()).collect();
    let t1 = Instant::now();
    assert!(fresh.complete_recovery(&kit.backup, &all, &kit.server_share[..], &v_acc).is_ok());
    let largest = t1.elapsed();
    eprintln!("oversized bundle rejected in {rejected:?}, largest allowed bundle (16 shares) in {largest:?}");
    assert!(rejected.as_millis() < 50, "{rejected:?}");
    // generous bound so it also holds in debug builds
    assert!(largest.as_millis() < 2000, "{largest:?}");
}

// ── Strict Ed25519 ──

/// R = identity, S = 0
fn universal_sig() -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[0] = 1;
    sig
}

#[test]
fn small_order_and_noncanonical_ed25519_keys_rejected() {
    let sig = universal_sig();
    let mut id = [0u8; 32];
    id[0] = 1;
    // with non-strict verification this one signature verifies every message under the identity key
    assert!(VerifyingKey::from_bytes(&id).unwrap().verify(b"a", &Signature::from_bytes(&sig)).is_ok());
    for m in [&b"a"[..], b"gori-vouch", b"", &[0u8; 32]] {
        assert!(!Core::verify(&id, m, &sig), "identity key");
    }
    // non-canonical: y = p + 1 (= identity), the same with the sign bit set, and -0
    let mut nc: [u8; 32] = hex::decode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap().try_into().unwrap();
    assert!(!Core::verify(&nc, b"x", &sig));
    nc[31] = 0xff;
    assert!(!Core::verify(&nc, b"x", &sig));
    let mut neg0 = id;
    neg0[31] |= 0x80;
    assert!(!Core::verify(&neg0, b"x", &sig));
    // order-8 keys: no message verifies
    for t in EIGHT_TORSION.iter() {
        let tk = t.compress().to_bytes();
        assert_eq!((0..64u8).filter(|i| Core::verify(&tk, &[*i], &sig)).count(), 0);
        assert!(crypto::ed25519_key_strict(&tk).is_none());
    }
    // non-canonical encoding of a large-order point (y + p): it decompresses but is not canonical
    let p_le: [u8; 32] = hex::decode("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap().try_into().unwrap();
    let mut found = 0;
    for k in 2u8..19 {
        let mut enc = p_le;
        enc[0] = enc[0].wrapping_add(k); // p + k (k ≤ 18, so no overflow)
        if let Some(pt) = CompressedEdwardsY(enc).decompress() {
            if !pt.is_small_order() {
                assert!(VerifyingKey::from_bytes(&enc).is_ok(), "dalek decompresses it");
                assert!(crypto::ed25519_key_strict(&enc).is_none(), "the strict check rejects y=p+{k}");
                found += 1;
            }
        }
    }
    assert!(found > 0, "must find at least one non-canonical encoding");
    // the honest key is accepted
    let honest = crypto::ed25519_public(&[7u8; 32]);
    assert!(crypto::ed25519_key_strict(&honest).is_some());
}

fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (Scalar::from_bytes_mod_order(a), prefix)
}

fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    Scalar::from_hash(h)
}

#[test]
fn malleability_mixed_order_r_and_mixed_order_key() {
    let seed = [9u8; 32];
    let pk = crypto::ed25519_public(&seed);
    let msg = b"vouch";
    let sig = crypto::ed25519_sign(&seed, msg);
    assert!(Core::verify(&pk, msg, &sig));
    // S + ℓ
    let ell: [u8; 32] = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap().try_into().unwrap();
    let mut sb = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + ell[i] as u16 + carry;
        sb[i] = v as u8;
        carry = v >> 8;
    }
    let mut mal = sig;
    mal[32..].copy_from_slice(&sb);
    assert!(!Core::verify(&pk, msg, &mal), "S+ℓ");
    let mut flip = sig;
    flip[31] ^= 0x80;
    assert!(!Core::verify(&pk, msg, &flip), "R sign bit");

    // mixed-order R: the cofactored equation (noble, ZIP-215) accepts it, strict verification rejects it
    let (a, prefix) = expand(&seed);
    let mut hr = Sha512::new();
    hr.update(prefix);
    hr.update(msg);
    let r = Scalar::from_hash(hr);
    let rp = r * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    let rb = rp.compress().to_bytes();
    let k = challenge(&rb, &pk, msg);
    let s2 = r + k * a;
    let mut msig = [0u8; 64];
    msig[..32].copy_from_slice(&rb);
    msig[32..].copy_from_slice(&s2.to_bytes());
    let apt = CompressedEdwardsY(pk).decompress().unwrap();
    assert!((rp + k * apt - s2 * ED25519_BASEPOINT_POINT).mul_by_cofactor().is_identity(), "the cofactored equation holds");
    assert!(!Core::verify(&pk, msg, &msig));

    // mixed-order public key A' = aB + T: a ground signature that also satisfies the cofactorless equation is
    // accepted by dalek's verify and verify_strict. The strict key check (torsion-free) rejects the key itself
    let a_mixed = (a * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1]).compress().to_bytes();
    let mut made = None;
    'grind: for nonce in 0u32..512 {
        let r = Scalar::from(nonce + 1);
        for t in EIGHT_TORSION.iter() {
            let big_r = r * ED25519_BASEPOINT_POINT + t;
            let rb = big_r.compress().to_bytes();
            let k = challenge(&rb, &a_mixed, msg);
            let s = r + k * a;
            let mut sg = [0u8; 64];
            sg[..32].copy_from_slice(&rb);
            sg[32..].copy_from_slice(&s.to_bytes());
            let vk = VerifyingKey::from_bytes(&a_mixed).unwrap();
            if vk.verify_strict(msg, &Signature::from_bytes(&sg)).is_ok() {
                made = Some(sg);
                break 'grind;
            }
        }
    }
    let sg = made.expect("grind a signature that verifies under the mixed-order key (1 in 8)");
    assert!(VerifyingKey::from_bytes(&a_mixed).unwrap().verify(msg, &Signature::from_bytes(&sg)).is_ok());
    assert!(!Core::verify(&a_mixed, msg, &sg), "strict verification rejects the mixed-order key");
    assert!(crypto::ed25519_key_strict(&a_mixed).is_none());
}

// ── Domain separation of signed statements ──

#[test]
fn encryption_key_signature_never_passes_as_device_certificate() {
    let mut v = core(70);
    let acc = v.generate(Slot::Account);
    let dev = v.generate(Slot::Device);
    let enc = v.generate(Slot::Enc);

    // a legacy (v1) encryption-key signature: a plain signature over the 32-byte public key
    let legacy_enc_sig = v.sign(Slot::Account, &enc).unwrap();

    // v2: a distinct prefix for each purpose
    let cert = v.sign_device_certificate().unwrap();
    let enc_sig = v.sign_encryption_key().unwrap();
    assert!(Core::verify(&acc, &crypto::device_cert_message(&dev), &cert));
    assert!(Core::verify(&acc, &crypto::enc_key_message(&enc), &enc_sig));
    // they never pass as each other, nor as the legacy form
    for (m, s) in [
        (crypto::device_cert_message(&enc), &enc_sig),
        (crypto::device_cert_message(&enc), &legacy_enc_sig),
        (crypto::enc_key_message(&dev), &cert),
        (dev.to_vec(), &cert),
        (enc.to_vec(), &enc_sig),
    ] {
        assert!(!Core::verify(&acc, &m, s));
    }

    // general signing cannot produce a reserved statement, so the JavaScript layer cannot obtain a v2 certificate
    // over bytes it chose
    for slot in [Slot::Account, Slot::Device] {
        assert_eq!(v.sign(slot, &crypto::device_cert_message(&dev)).unwrap_err(), Error::ReservedStatement);
        assert_eq!(v.sign(slot, &crypto::enc_key_message(&enc)).unwrap_err(), Error::ReservedStatement);
        assert_eq!(v.sign(slot, b"gori-core/anything").unwrap_err(), Error::ReservedStatement);
    }
    // outside the reserved namespace signing works as before (the app's own statements)
    assert!(v.sign(Slot::Account, b"app-statement-v1\0...").is_ok());
    assert!(v.sign(Slot::Account, b"gori-cor").is_ok());

    // a device certificate covers only this core's device key, and fails without the key
    let mut no_dev = core(71);
    no_dev.generate(Slot::Account);
    assert_eq!(no_dev.sign_device_certificate().unwrap_err(), Error::NoDeviceKey);
    assert_eq!(no_dev.sign_encryption_key().unwrap_err(), Error::NoEncryptionKey);
    assert_eq!(core(72).sign_device_certificate().unwrap_err(), Error::NoAccountKey);
    // the legacy certify_device also refuses a device key that is not strict
    let mut ident = [0u8; 32];
    ident[0] = 1;
    assert_eq!(v.certify_device(&ident).unwrap_err(), Error::WeakKey);
}

// ── C ABI: output pointers are validated before any state changes ──

#[test]
fn ffi_validates_outputs_before_mutating() {
    unsafe {
        let c = ffi::gori_core_new();
        let mut pubk = [0u8; 32];
        let mut has = 0u8;
        assert_eq!(ffi::gori_generate(c, 4, pubk.as_mut_ptr()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_generate(c, u32::MAX, pubk.as_mut_ptr()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_generate(std::ptr::null(), 0, pubk.as_mut_ptr()), Error::InvalidArgument.code());

        // gori_generate: with a NULL out it neither creates nor replaces the slot
        assert_eq!(ffi::gori_generate(c, 2, std::ptr::null_mut()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_has(c, 2, &mut has), 0);
        assert_eq!(has, 0, "enc slot created despite a NULL out");
        assert_eq!(ffi::gori_generate(c, 2, pubk.as_mut_ptr()), 0);
        let first = pubk;
        assert_eq!(ffi::gori_generate(c, 2, std::ptr::null_mut()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_public_key(c, 2, pubk.as_mut_ptr()), 0);
        assert_eq!(pubk, first, "enc slot replaced despite a NULL out");

        // gori_begin_recovery: if any out is NULL no temporary key is created
        let mut created = 0u8;
        assert_eq!(ffi::gori_begin_recovery(c, std::ptr::null_mut(), &mut created), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_begin_recovery(c, pubk.as_mut_ptr(), std::ptr::null_mut()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_has(c, 3, &mut has), 0);
        assert_eq!(has, 0, "temporary key created despite a NULL out");

        // gori_complete_recovery: even with a genuine bundle, a NULL out leaves the slots and the temporary key alone
        let (mut b, b_acc) = member(80);
        let (mut gs, gp) = guardians(81, 2);
        let kit = b.prepare_recovery(&gp, 2).unwrap();
        let (mut tmp, mut created) = ([0u8; 32], 0u8);
        assert_eq!(ffi::gori_begin_recovery(c, tmp.as_mut_ptr(), &mut created), 0);
        assert_eq!(created, 1);
        let r: Vec<Vec<u8>> = (0..2).map(|i| gs[i].reseal_share(&kit.guardian_shares[i], &tmp).unwrap()).collect();
        let ptrs: Vec<*const u8> = r.iter().map(|v| v.as_ptr()).collect();
        let lens: Vec<usize> = r.iter().map(|v| v.len()).collect();
        let (mut ap, mut ep) = ([0u8; 32], [0u8; 32]);
        let call = |out_a: *mut u8, out_e: *mut u8, expected: &[u8]| {
            ffi::gori_complete_recovery(
                c,
                kit.backup.as_ptr(),
                kit.backup.len(),
                ptrs.as_ptr(),
                lens.as_ptr(),
                ptrs.len(),
                kit.server_share.as_ptr(),
                32,
                expected.as_ptr(),
                expected.len(),
                out_a,
                out_e,
            )
        };
        assert_eq!(call(std::ptr::null_mut(), ep.as_mut_ptr(), &b_acc), Error::InvalidArgument.code());
        assert_eq!(call(ap.as_mut_ptr(), std::ptr::null_mut(), &b_acc), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_has(c, 0, &mut has), 0);
        assert_eq!(has, 0, "account slot created despite a NULL out");
        assert_eq!(ffi::gori_has(c, 3, &mut has), 0);
        assert_eq!(has, 1, "temporary key removed despite a NULL out");
        // this core already has an enc key (first, above): it is not overwritten
        assert_eq!(call(ap.as_mut_ptr(), ep.as_mut_ptr(), &b_acc), Error::KeyConflict.code());
        assert_eq!(ffi::gori_public_key(c, 2, pubk.as_mut_ptr()), 0);
        assert_eq!(pubk, first);
        // a different expected account
        let other = crypto::ed25519_public(&[1u8; 32]);
        assert_eq!(call(ap.as_mut_ptr(), ep.as_mut_ptr(), &other), Error::AccountMismatch.code());
        // expected account: wrong length, NULL
        assert_eq!(call(ap.as_mut_ptr(), ep.as_mut_ptr(), &b_acc[..31]), Error::InvalidArgument.code());
        assert_eq!(
            ffi::gori_complete_recovery(
                c, kit.backup.as_ptr(), kit.backup.len(), ptrs.as_ptr(), lens.as_ptr(), 2,
                kit.server_share.as_ptr(), 32, std::ptr::null(), 32, ap.as_mut_ptr(), ep.as_mut_ptr()
            ),
            Error::InvalidArgument.code()
        );
        // the share count limit is checked before the arrays are read (no overflow even with NULL arrays)
        assert_eq!(
            ffi::gori_complete_recovery(
                c, kit.backup.as_ptr(), kit.backup.len(), std::ptr::null(), std::ptr::null(), MAX_GUARDIANS + 1,
                kit.server_share.as_ptr(), 32, b_acc.as_ptr(), 32, ap.as_mut_ptr(), ep.as_mut_ptr()
            ),
            Error::BadShareCount.code()
        );
        // count > 0 with NULL arrays
        assert_eq!(
            ffi::gori_complete_recovery(
                c, kit.backup.as_ptr(), kit.backup.len(), std::ptr::null(), std::ptr::null(), 2,
                kit.server_share.as_ptr(), 32, b_acc.as_ptr(), 32, ap.as_mut_ptr(), ep.as_mut_ptr()
            ),
            Error::InvalidArgument.code()
        );

        // non-UTF-8 handle, NULL data with len > 0, NULL out
        let bad = [0xffu8, 0xfe, 0];
        let mut buf = ffi::GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        assert_eq!(ffi::gori_encrypt(c, bad.as_ptr() as *const _, b"x".as_ptr(), 1, &mut buf), Error::InvalidArgument.code());
        let h = CString::new("00").unwrap();
        assert_eq!(ffi::gori_encrypt(c, h.as_ptr(), std::ptr::null(), 5, &mut buf), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_create_content_key(c, std::ptr::null_mut()), Error::InvalidArgument.code());

        // prepare: limit, overflow, NULL out
        let mut u = [0u8; 32];
        let mut sl = 0usize;
        let mut b2 = ffi::GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        let mut b3 = ffi::GoriBuf { ptr: std::ptr::null_mut(), len: 0 };
        assert_eq!(
            ffi::gori_prepare_recovery(c, [0u8; 1].as_ptr(), usize::MAX / 16, 2, &mut b2, u.as_mut_ptr(), &mut b3, &mut sl),
            Error::BadShareCount.code()
        );
        assert_eq!(
            ffi::gori_prepare_recovery(c, [0u8; 64].as_ptr(), 2, 2, &mut b2, std::ptr::null_mut(), &mut b3, &mut sl),
            Error::InvalidArgument.code()
        );

        // dedicated signing functions: NULL out, missing key
        let mut sig = [0u8; 64];
        assert_eq!(ffi::gori_sign_device_certificate(c, std::ptr::null_mut()), Error::InvalidArgument.code());
        assert_eq!(ffi::gori_sign_device_certificate(c, sig.as_mut_ptr()), Error::NoAccountKey.code());
        assert_eq!(ffi::gori_sign_encryption_key(std::ptr::null(), sig.as_mut_ptr()), Error::InvalidArgument.code());
        // general signing refuses reserved statements
        let mut acc_pub = [0u8; 32];
        assert_eq!(ffi::gori_generate(c, 0, acc_pub.as_mut_ptr()), 0);
        let reserved = crypto::enc_key_message(&first);
        assert_eq!(
            ffi::gori_sign(c, 0, reserved.as_ptr(), reserved.len(), sig.as_mut_ptr()),
            Error::ReservedStatement.code()
        );
        assert_eq!(ffi::gori_sign_encryption_key(c, sig.as_mut_ptr()), 0);
        assert_eq!(ffi::gori_verify(acc_pub.as_ptr(), 32, reserved.as_ptr(), reserved.len(), sig.as_ptr(), 64), 1);
        ffi::gori_core_free(c);
    }
}
